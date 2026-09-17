// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Helpers shared by the JAM unit tests.

use super::{
    codec::DecodeError,
    params::Params,
    tree::{HeaderTree, Insert, InsertError, VerifySuccess},
    types::{Hash, Header},
};
use alloc::vec::Vec;
use core::fmt::Debug;
use std::path::{Path, PathBuf};

/// The parameters of PolkaJam's tiny test network.
pub(crate) fn tiny_params() -> Params {
    Params {
        epoch_len: 12,
        max_validators: 6,
        slot_seconds: 6,
        epoch_tail_start: 10,
        max_tickets_per_ext: 3,
        deposit_per_item: 10,
        deposit_per_byte: 1,
        deposit_per_account: 100,
        core_count: 2,
        min_turnaround_period: 32,
        max_accumulate_gas: 10_000_000,
        max_is_authorized_gas: 50_000_000,
        max_refine_gas: 1_000_000_000,
        block_gas_limit: 20_000_000,
        recent_block_count: 8,
        max_work_items: 16,
        max_dependencies: 8,
        max_lookup_anchor_age: 24,
        auth_window: 8,
        auth_queue_len: 80,
        rotation_period: 4,
        max_extrinsics: 128,
        availability_timeout: 5,
        max_authorizer_code_size: 64_000,
        max_input: 13_791_360,
        max_service_code_size: 4_000_000,
        max_imports: 3072,
        max_report_elective_data: 48 * 1024,
        transfer_memo_size: 128,
        max_exports: 3072,
    }
}

/// A markless, unsigned header at `slot` on `parent`, every other field zero.
pub(crate) fn header(parent: Hash, slot: u32) -> Header {
    Header {
        parent,
        prior_state_root: [0; 32],
        extrinsic_hash: [0; 32],
        slot,
        epoch_mark: None,
        tickets_mark: None,
        author_index: 0,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    }
}

/// Decodes a JSON hex string, with or without a `0x` prefix.
pub(crate) fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).unwrap()
}

pub(crate) fn json_array<const N: usize>(value: &serde_json::Value) -> [u8; N] {
    json_bytes(value).try_into().unwrap()
}

/// The library's fixture directory, `src/jam/fixtures`.
pub(crate) fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jam/fixtures")
}

pub(crate) fn load_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

/// Every JSON file below `dir`, recursively, in sorted order.
pub(crate) fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(json_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Asserts that `decode` rejects every proper prefix of `bytes`.
#[track_caller]
pub(crate) fn assert_prefixes_rejected<T, E>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, E>) {
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err(), "prefix {end}");
    }
}

/// Asserts that `decode` accepts exactly `bytes`: every proper prefix fails and
/// one byte more fails with `TrailingBytes`. Returns the decoded value.
#[track_caller]
pub(crate) fn assert_strict<T, E: From<DecodeError> + PartialEq + Debug>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, E>,
) -> T {
    assert_prefixes_rejected(bytes, &decode);
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert_eq!(
        decode(&extended).err(),
        Some(E::from(DecodeError::TrailingBytes))
    );
    decode(bytes).unwrap()
}

/// Verifies `header` as a child of the retained parent it names, then inserts it.
pub(crate) fn verify_and_insert(
    tree: &mut HeaderTree,
    header: Header,
    now: u64,
) -> Result<Insert, InsertError> {
    match tree.verify(header.parent, header, now)? {
        VerifySuccess::AlreadyKnown => Ok(Insert::AlreadyKnown),
        VerifySuccess::Verified(verified) => tree.insert_verified(verified),
    }
}
