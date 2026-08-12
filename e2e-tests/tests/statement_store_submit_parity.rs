// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use log::info;
use serde_json::{json, Value};
use smoldot::network::codec::MAX_STATEMENT_SIZE;
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;

/// Expected answers of light and full nodes
enum Expected {
    /// Both answer are same
    Same(SubmitAnswer),
    /// The two answers are different on purpose
    Divergent {
        light_node: SubmitAnswer,
        full_node: SubmitAnswer,
        why: &'static str,
    },
}

/// One statement submitted to both clients
struct Case {
    name: &'static str,
    hex: String,
    prelude: Vec<String>,
    expected: Expected,
}

fn resolved(value: Value) -> SubmitAnswer {
    SubmitAnswer::Resolved(value)
}

const NO_STORE: &str =
    "compares the submission against what a store already holds, which a light client has no \
     equivalent of and cannot fetch";

const NO_STATE_READ: &str =
    "an allowance lives in chain state, and a light client reads chain state over the network, so \
     matching this would put a storage request in front of every submission";

const BAD_PROOF_COSTS_CPU: &str =
    "telling a bad proof from a good one means verifying a signature, and a light client runs \
     where CPU is the scarce resource, so only the presence of a proof is checked";

/// `statement_submit` answers the same way on smoldot and on a full node, wherever a light client
/// can answer at all.
///
/// The full node is asked first, from here; its answers are handed to the shared body, which asks
/// smoldot and compares.
///
/// Three answers get no case:
///
/// - `StoreFull` would mean pushing the global 2 GiB `DEFAULT_MAX_TOTAL_SIZE` through the
///   collator, which no chain spec can shrink, and it is another store-side rejection, so
///   `rejected_account_full` already covers what it would say about smoldot.
/// - `InternalError` reports a database failure, which a submission cannot provoke.
/// - `KnownExpired` would mean storing a statement and waiting for it to expire, and it shares
///   the guard `known` already asserts.
#[tokio::test(flavor = "multi_thread")]
async fn submit_answers_match_full_node() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let (allowed_seed, allowed_key) = test_keypair();
    let (unfunded_seed, _) = keypair_from_byte(2);
    let (fillable_seed, fillable_key) = keypair_from_byte(3);

    let base_dir = resolve_base_dir()?;
    let para_spec_path =
        create_para_chain_spec_with_allowances(&[allowed_key, fillable_key], &base_dir)?;
    let network = spawn_network(&base_dir, &para_spec_path).await?;
    info!("Network spawned");

    let (relay_base, para_base) = spawned_chain_spec_paths(&network)?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();
    let (relay_spec_path, para_spec_path) =
        prepare_runtime_specs(&network, &relay_base, &para_base, &base_dir_str).await?;

    ensure_smoldot_built();
    ensure_js_deps_installed();

    let topic = [0u8; 32];
    let channel = [7u8; 32];
    let flawed =
        |data: &str, flaw| create_flawed_statement(&allowed_seed, &topic, data.as_bytes(), flaw);

    let too_large = flawed("parity-too-large", StatementFlaw::TooLarge);
    let over_allowance = flawed("parity-over-allowance", StatementFlaw::DataOverAllowance);

    // `submitted_size` counts SCALE bytes, which is half the hex minus the `0x`. The allowance is
    // measured against the data field alone, so that one is the payload length.
    let too_large_size = (too_large.len() - 2) / 2;

    let cases = vec![
        Case {
            name: "new",
            hex: create_test_statement(&allowed_seed, &topic, b"parity-new"),
            prelude: Vec::new(),
            expected: Expected::Same(resolved(json!({"status": "new"}))),
        },
        Case {
            name: "known",
            // Resubmitting a statement the store already holds. `known` is never the answer: it is
            // reserved for a source that may not resubmit, and an RPC submission always may.
            hex: create_test_statement(&allowed_seed, &topic, b"parity-known"),
            prelude: vec![create_test_statement(
                &allowed_seed,
                &topic,
                b"parity-known",
            )],
            expected: Expected::Same(resolved(json!({"status": "new"}))),
        },
        Case {
            name: "rejected_no_allowance",
            hex: create_test_statement(&unfunded_seed, &topic, b"parity-no-allowance"),
            prelude: Vec::new(),
            expected: Expected::Divergent {
                light_node: resolved(json!({"status": "new"})),
                full_node: resolved(json!({"status": "rejected", "reason": "noAllowance"})),
                why: NO_STATE_READ,
            },
        },
        Case {
            name: "rejected_data_too_large",
            hex: over_allowance,
            prelude: Vec::new(),
            expected: Expected::Divergent {
                light_node: resolved(json!({"status": "new"})),
                full_node: resolved(json!({
                    "status": "rejected",
                    "reason": "dataTooLarge",
                    "submitted_size": DATA_OVER_ALLOWANCE_LEN,
                    "available_size": ALLOWANCE_MAX_SIZE,
                })),
                why: NO_STATE_READ,
            },
        },
        Case {
            name: "rejected_channel_priority_too_low",
            hex: create_statement_with_expiry(
                &allowed_seed,
                &topic,
                b"parity-channel-low",
                LOWER_PRIORITY_EXPIRY,
                Some(channel),
            ),
            prelude: vec![create_statement_with_expiry(
                &allowed_seed,
                &topic,
                b"parity-channel-high",
                FAR_FUTURE_EXPIRY,
                Some(channel),
            )],
            expected: Expected::Divergent {
                light_node: resolved(json!({"status": "new"})),
                full_node: resolved(json!({
                    "status": "rejected",
                    "reason": "channelPriorityTooLow",
                    "submitted_expiry": LOWER_PRIORITY_EXPIRY,
                    "min_expiry": FAR_FUTURE_EXPIRY,
                })),
                why: NO_STORE,
            },
        },
        Case {
            name: "rejected_account_full",
            hex: create_statement_with_expiry(
                &fillable_seed,
                &topic,
                b"parity-account-full",
                LOWER_PRIORITY_EXPIRY,
                None,
            ),
            // Every filler shares one expiry: `by_priority` is keyed `{ hash, expiry }` and so
            // iterates in hash order, leaving `min_expiry` undecided if they differed.
            prelude: (0..ALLOWANCE_MAX_COUNT)
                .map(|i| {
                    create_statement_with_expiry(
                        &fillable_seed,
                        &topic,
                        format!("parity-filler-{i}").as_bytes(),
                        FAR_FUTURE_EXPIRY,
                        None,
                    )
                })
                .collect(),
            expected: Expected::Divergent {
                light_node: resolved(json!({"status": "new"})),
                full_node: resolved(json!({
                    "status": "rejected",
                    "reason": "accountFull",
                    "submitted_expiry": LOWER_PRIORITY_EXPIRY,
                    "min_expiry": FAR_FUTURE_EXPIRY,
                })),
                why: NO_STORE,
            },
        },
        Case {
            name: "invalid_no_proof",
            hex: flawed("parity-no-proof", StatementFlaw::NoProof),
            prelude: Vec::new(),
            expected: Expected::Same(resolved(json!({"status": "invalid", "reason": "noProof"}))),
        },
        Case {
            name: "invalid_bad_proof",
            hex: flawed("parity-bad-proof", StatementFlaw::BadProof),
            prelude: Vec::new(),
            expected: Expected::Divergent {
                light_node: resolved(json!({"status": "new"})),
                full_node: resolved(json!({"status": "invalid", "reason": "badProof"})),
                why: BAD_PROOF_COSTS_CPU,
            },
        },
        Case {
            name: "invalid_encoding_too_large",
            hex: too_large,
            prelude: Vec::new(),
            // Carries no proof either, so it pins the order: size is checked before the proof.
            expected: Expected::Same(resolved(json!({
                "status": "invalid",
                "reason": "encodingTooLarge",
                "submitted_size": too_large_size,
                "max_size": MAX_STATEMENT_SIZE,
            }))),
        },
        Case {
            name: "invalid_already_expired",
            // Carries no proof either, so this also pins the order: expiry is checked first.
            hex: flawed("parity-expired", StatementFlaw::ExpiredAndUnsigned),
            prelude: Vec::new(),
            expected: Expected::Same(resolved(
                json!({"status": "invalid", "reason": "alreadyExpired"}),
            )),
        },
        Case {
            name: "decode_failure",
            hex: "0xffff".to_owned(),
            prelude: Vec::new(),
            // Both answer polkadot-sdk's statement-store error code. It is the only code that side
            // uses for a submission it couldn't process, so a client needs no second one.
            expected: Expected::Same(SubmitAnswer::Rejected(7001)),
        },
    ];

    // The full node answers every case before smoldot is started, so a statement smoldot
    // broadcasts cannot reach the collator in time to change an answer already recorded.
    let alice_rpc = network.get_node("alice")?.rpc().await?;
    let mut payload = Vec::with_capacity(cases.len());

    for case in &cases {
        for (i, prelude) in case.prelude.iter().enumerate() {
            let answer = submit_statement_answer(&alice_rpc, prelude).await;
            assert_eq!(
                answer,
                resolved(json!({"status": "new"})),
                "{}: the full node refused prelude statement {i} with {answer}, so the case cannot \
                 provoke what it is meant to",
                case.name,
            );
        }

        let full_node = submit_statement_answer(&alice_rpc, &case.hex).await;

        let (want_light_node, want_full_node, why) = match &case.expected {
            Expected::Same(answer) => (answer, answer, None),
            Expected::Divergent {
                light_node,
                full_node,
                why,
            } => (light_node, full_node, Some(*why)),
        };

        info!("{:<35} full node answered {full_node}", case.name);
        assert_eq!(
            full_node, *want_full_node,
            "the full node answered {} with {full_node}, expected {want_full_node}",
            case.name,
        );

        // The full node's answer is asserted above, in Rust, where a `u64` expiry keeps its
        // precision. The copy handed to the body is only there for its log line: JSON numbers past
        // 2^53 lose their tail once the body parses them.
        payload.push(json!({
            "name": case.name,
            "hex": case.hex,
            "fullNode": full_node.to_json(),
            "expected": want_light_node.to_json(),
            "why": why,
        }));
    }

    let cases_file = tempfile::NamedTempFile::new()?;
    std::fs::write(
        cases_file.path(),
        serde_json::to_vec(&Value::Array(payload))?,
    )?;

    info!("Handing {} cases to smoldot", cases.len());
    run_shared_test(
        Host::Node,
        "statement_store_submit_parity",
        &[
            (
                "RELAY_CHAIN_SPEC",
                relay_spec_path.to_str().expect("UTF-8 path"),
            ),
            (
                "PARA_CHAIN_SPEC",
                para_spec_path.to_str().expect("UTF-8 path"),
            ),
            (
                "PARITY_CASES",
                cases_file.path().to_str().expect("UTF-8 path"),
            ),
        ],
    )
    .await
    .map_err(|e| anyhow::anyhow!("smoldot answered at least one case unexpectedly: {e}"))?;

    info!("All {} cases answered as expected", cases.len());
    Ok(())
}
