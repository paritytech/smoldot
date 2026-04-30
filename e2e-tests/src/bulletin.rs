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

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use smoldot::libp2p::cid::{Cid, CidPrefix, MultihashType};

/// Para id of the bulletin chain. Matches polkadot-bulletin-chain's own
/// stress-test fixture.
pub const PARA_ID: u32 = 2487;

/// Default snapshot height target. Must exceed 1000 blocks.
pub const DEFAULT_SNAPSHOT_HEIGHT: u64 = 1024;

/// Index after which the partial bulletin snapshot is taken.
///
/// The generator produces two bulletin DB snapshots from one network run:
///
/// - `bulletin-full.tgz` — every payload in [`payloads`] is injected.
/// - `bulletin-partial.tgz` — only the first `PARTIAL_FORK_INDEX` payloads
///   are injected; captured before the rest go in.
///
/// The CI test for mixed availability loads `bulletin-full` on one
/// collator and `bulletin-partial` on another, then fetches a CID that
/// exists only in `bulletin-full` to verify smoldot still finds it via
/// gossip when a peer reports `DontHave`.
pub const PARTIAL_FORK_INDEX: usize = 2;

/// CIDv1 multicodec for the `raw` codec.
const CODEC_RAW: u64 = 0x55;

/// One injected payload. The generator must call
/// `transactionStorage::authorize_account` for the submitting account
/// before any `store` extrinsic succeeds. Per-tx ceiling is 2 MiB.
pub struct Payload {
    pub label: &'static str,
    pub content: &'static [u8],
    /// Whether the partial bulletin snapshot also contains this CID.
    pub on_partial: bool,
}

impl Payload {
    /// CID derived from the payload using BLAKE2b-256 over CIDv1 raw, the
    /// same way `pallet-transaction-storage` does.
    pub fn predicted_cid(&self) -> String {
        blake2b256_cid(self.content).to_string()
    }

    /// Hex-encoded SHA-256 of the payload, written into the manifest for
    /// independent verification by the CI test.
    pub fn sha256_hex(&self) -> String {
        hex::encode(Sha256::digest(self.content))
    }

    pub fn size(&self) -> u64 {
        self.content.len() as u64
    }
}

/// Deterministic payloads the generator injects and the CI tests assert
/// on. See [`PARTIAL_FORK_INDEX`] for what `both-*` and `full-only-*`
/// labels mean. Order matters: items at `[..PARTIAL_FORK_INDEX]` go in
/// before the partial snapshot is captured.
pub fn payloads() -> Vec<Payload> {
    vec![
        Payload {
            label: "both-small",
            content: b"smoldot-bitswap-both-small",
            on_partial: true,
        },
        Payload {
            label: "both-4kib",
            content: rand_4k(),
            on_partial: true,
        },
        Payload {
            label: "full-only-small",
            content: b"smoldot-bitswap-full-only-small",
            on_partial: false,
        },
        Payload {
            label: "full-only-1mib",
            content: rand_1m(),
            on_partial: false,
        },
    ]
}

/// 4 KiB pseudo-random payload, deterministic from a fixed seed.
fn rand_4k() -> &'static [u8] {
    static BUF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BUF.get_or_init(|| xorshift_fill(0xdead_beef_dead_beefu64, 4 * 1024))
        .as_slice()
}

/// 1 MiB pseudo-random payload, deterministic from a different seed.
fn rand_1m() -> &'static [u8] {
    static BUF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BUF.get_or_init(|| xorshift_fill(0xfeed_face_cafe_babeu64, 1024 * 1024))
        .as_slice()
}

fn xorshift_fill(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn cid_for(content: &[u8], mh: MultihashType) -> Cid {
    let prefix = build_prefix(mh).expect("hard-coded prefix is always valid");
    prefix.with_digest_of(content)
}

/// Build a CIDv1(raw, blake2b-256) for the given content. This matches the
/// CID under which `pallet-transaction-storage::store` content is served
/// over bitswap.
pub fn blake2b256_cid(content: &[u8]) -> Cid {
    cid_for(content, MultihashType::Blake2b256)
}

/// Build a CIDv1(raw, sha2-256) for the given content. Useful for negative
/// tests: a syntactically valid CID over content the bulletin chain
/// provably does not store.
pub fn sha256_cid(content: &[u8]) -> Cid {
    cid_for(content, MultihashType::Sha2_256)
}

fn build_prefix(mh: MultihashType) -> anyhow::Result<CidPrefix> {
    let mut bytes = Vec::with_capacity(8);
    write_leb128(&mut bytes, 1); // CIDv1
    write_leb128(&mut bytes, CODEC_RAW);
    write_leb128(&mut bytes, mh as u64);
    write_leb128(&mut bytes, mh.digest_size() as u64);
    CidPrefix::from_bytes(bytes).map_err(|e| anyhow::anyhow!("invalid prefix: {e}"))
}

fn write_leb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPayload {
    pub label: String,
    pub cid: String,
    pub sha256: String,
    pub size: u64,
    pub on_partial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveChecksums {
    pub relay_sha256: String,
    pub bulletin_full_sha256: String,
    pub bulletin_partial_sha256: String,
}

/// Manifest emitted alongside the snapshots by the generator. Bumping
/// `schema_version` is a breaking change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulletinManifest {
    pub schema_version: u32,
    pub snapshot_height: u64,
    pub bulletin_release_tag: String,
    pub polkadot_release_tag: String,
    pub payloads: Vec<ManifestPayload>,
    pub archives: ArchiveChecksums,
}