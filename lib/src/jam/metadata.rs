// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Network endpoints advertised in the active validator set's metadata.
//!
//! Each `ValidatorKey` in `C(8)` carries 128 bytes of metadata. JAMNP-S fixes
//! the first 18: a 16-byte IPv6 address (IPv4 as an IPv4-mapped address) and a
//! little-endian UDP port. PolkaJam (`jam-std-common/src/keyset.rs`,
//! `ValidatorMetadata`) puts its WebTransport P-256 identity in the next 33
//! bytes: one Y-parity byte (`0` even, `1` odd, not a SEC1 tag) followed by the
//! 32-byte X coordinate. That position is PolkaJam's convention, not the
//! specification's, so parsing is total and tolerant: anything unexpected
//! yields no key or port zero rather than an error.
//!
//! Nothing here is trusted beyond liveness. The curve point is validated by
//! the WebTransport layer, and every byte a discovered peer serves is verified
//! exactly as a bootnode's.

use crate::jam::{
    codec::{self, DecodeError},
    params::Params,
    types::{Ed25519Public, ValidatorKey},
};
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr};

const IP_BYTES: usize = 16;
const PORT_OFFSET: usize = IP_BYTES;
const PARITY_OFFSET: usize = PORT_OFFSET + 2;
const X_OFFSET: usize = PARITY_OFFSET + 1;

/// One active validator's identity and advertised endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEndpoint {
    pub ed25519: Ed25519Public,
    /// IPv4-mapped addresses are unmapped to [`IpAddr::V4`].
    pub ip: IpAddr,
    pub port: u16,
    /// `(x, y_odd)` when the metadata carries a P-256 key, else `None`.
    pub p256: Option<([u8; 32], bool)>,
}

impl ValidatorEndpoint {
    /// Total, never fails: unusable records yield `port == 0` or `p256 == None`.
    ///
    /// A parity byte other than 0 or 1, or an all-zero X coordinate
    /// (PolkaJam's `P256PeerId::ZERO`), means the validator has no P-256 key.
    pub fn from_validator(key: &ValidatorKey) -> Self {
        let metadata = &key.metadata;
        let ip = Ipv6Addr::from(core::array::from_fn::<u8, IP_BYTES, _>(|i| metadata[i]));
        let ip = match ip.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(ip),
        };
        let port = u16::from_le_bytes([metadata[PORT_OFFSET], metadata[PORT_OFFSET + 1]]);
        let x: [u8; 32] = core::array::from_fn(|i| metadata[X_OFFSET + i]);
        let y_odd = match metadata[PARITY_OFFSET] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        let p256 = y_odd.filter(|_| x != [0; 32]).map(|y_odd| (x, y_odd));
        Self {
            ed25519: key.ed25519,
            ip,
            port,
            p256,
        }
    }
}

/// Decode `C(8)`'s value: a natural-number count then 336-byte records (D12 layout).
///
/// This is the codec's own `C(8)` decoder; the count is bounded by
/// `Params::max_validators`.
pub fn decode_active_set(params: &Params, value: &[u8]) -> Result<Vec<ValidatorKey>, DecodeError> {
    codec::decode_active_validators(params, value)
}

#[cfg(test)]
mod tests;
