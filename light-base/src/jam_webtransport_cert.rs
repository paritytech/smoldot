// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Deterministic PolkaJam WebTransport certificate pins.
//!
//! Reproduces the exact certificate PolkaJam presents; not a general X.509 encoder.
//! These certificates have fake signatures; authentication relies on the certificate hash and
//! proof of possession of the subject key in the TLS handshake.
//!
//! X.509 identifies a certificate by its issuer and serial number. NSS, the certificate library of
//! Firefox, refuses a second, different certificate with a pair it has already seen
//! (`SEC_ERROR_REUSED_ISSUER_AND_SERIAL`) for the life of the browser process. PolkaJam therefore
//! gives every node and validity period its own pair: the issuer is
//! `CN=<the node's P-256 peer ID text>` and the serial number is the validity-period index, so that
//! one browser process can hold several nodes and keep each across certificate rotations. The
//! subject is `CN=jam`.

use alloc::{format, string::String, vec, vec::Vec};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::Digest as _;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const PERIOD_SECS: u64 = 10 * 24 * 3600;
const PADDING_SECS: u64 = 24 * 3600;
const ED25519_ALGORITHM: &[u8] = &[0x30, 5, 6, 3, 0x2b, 0x65, 0x70];
/// Common name of every certificate's subject.
const JAM_COMMON_NAME: &str = "jam";

/// Validated P-256 public key used as a WebTransport peer identity.
///
/// Constructed only through [`Self::from_text`], which validates and decompresses the curve point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256PeerId {
    x: [u8; 32],
    y: [u8; 32],
}

/// Invalid peer-ID text or curve point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display, derive_more::Error)]
pub enum P256PeerIdParseError {
    /// Text must contain exactly 53 ASCII bytes.
    #[display("peer ID must contain 53 ASCII bytes")]
    BadLength,
    /// Only `o` (odd Y) and `v` (even Y) identify P-256 keys.
    #[display("invalid P-256 peer ID prefix")]
    BadPrefix,
    /// Only the lowercase base32 alphabet is accepted.
    #[display("invalid peer ID character")]
    BadCharacter,
    /// The unused high four bits of the last symbol must be zero.
    #[display("nonzero trailing peer ID bits")]
    NonZeroTrailingBits,
    /// The compressed coordinate does not identify a P-256 curve point.
    #[display("invalid P-256 curve point")]
    InvalidPoint,
}

impl P256PeerId {
    /// Parses the canonical PolkaJam text form and validates the curve point.
    pub fn from_text(s: &str) -> Result<Self, P256PeerIdParseError> {
        if !s.is_ascii() {
            return Err(P256PeerIdParseError::BadCharacter);
        }
        let bytes = s.as_bytes();
        if bytes.len() != 53 {
            return Err(P256PeerIdParseError::BadLength);
        }
        let y_odd = match bytes[0] {
            b'o' => true,
            b'v' => false,
            _ => return Err(P256PeerIdParseError::BadPrefix),
        };
        let mut x = [0; 32];
        for (symbol, &byte) in bytes[1..].iter().enumerate() {
            let value = match byte {
                b'a'..=b'z' => byte - b'a',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(P256PeerIdParseError::BadCharacter),
            };
            if symbol == 51 && value > 1 {
                return Err(P256PeerIdParseError::NonZeroTrailingBits);
            }
            for bit in 0..5 {
                let position = symbol * 5 + bit;
                if position < 256 {
                    x[position / 8] |= ((value >> bit) & 1) << (position % 8);
                }
            }
        }
        let mut compressed = [0; 33];
        compressed[0] = if y_odd { 3 } else { 2 };
        compressed[1..].copy_from_slice(&x);
        let key = p256::PublicKey::from_sec1_bytes(&compressed)
            .map_err(|_| P256PeerIdParseError::InvalidPoint)?;
        let point = key.to_encoded_point(false);
        let y = point.y().ok_or(P256PeerIdParseError::InvalidPoint)?;
        Ok(Self { x, y: (*y).into() })
    }

    /// Big-endian X coordinate.
    pub fn x(&self) -> &[u8; 32] {
        &self.x
    }

    /// Whether the uncompressed Y coordinate is odd.
    pub fn y_odd(&self) -> bool {
        self.y[31] & 1 != 0
    }

    /// Returns the 53-byte text form, using PolkaJam's little-endian base32 bit order.
    pub fn to_text(&self) -> String {
        let mut text = String::with_capacity(53);
        text.push(if self.y_odd() { 'o' } else { 'v' });
        for position in (0..256).step_by(5) {
            let low = self.x[position / 8];
            let high = self.x.get(position / 8 + 1).copied().unwrap_or(0);
            let window = u16::from(low) | (u16::from(high) << 8);
            text.push(char::from(
                ALPHABET[usize::from((window >> (position % 8)) & 31)],
            ));
        }
        text
    }

    /// Returns the validated key as a 65-byte uncompressed SEC1 point.
    pub fn to_uncompressed_sec1(&self) -> [u8; 65] {
        let mut point = [0; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(&self.x);
        point[33..].copy_from_slice(&self.y);
        point
    }
}

/// A ten-day Unix-time period, padded by one day on either side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityPeriod(pub u64);

impl ValidityPeriod {
    /// Period containing the given Unix timestamp.
    pub fn from_unix_secs(timestamp: u64) -> Self {
        Self(timestamp / PERIOD_SECS)
    }

    fn begin(self) -> time::OffsetDateTime {
        date_time(
            self.0
                .saturating_mul(PERIOD_SECS)
                .saturating_sub(PADDING_SECS),
        )
    }

    fn end(self) -> time::OffsetDateTime {
        date_time(
            self.0
                .saturating_add(1)
                .saturating_mul(PERIOD_SECS)
                .saturating_add(PADDING_SECS),
        )
    }
}

fn date_time(timestamp: u64) -> time::OffsetDateTime {
    // PolkaJam's certificates cap dates at the end of year 9999. Clamp explicitly, so that
    // another dependency enabling `time/large-dates` cannot change the DER.
    time::OffsetDateTime::from_unix_timestamp(
        i64::try_from(timestamp.min(253_402_300_799)).unwrap_or(i64::MAX),
    )
    .unwrap_or(time::PrimitiveDateTime::MAX.assume_utc())
}

/// Rebuilds PolkaJam's deterministic certificate, including its 64-byte zero signature: issuer
/// `CN=<peer ID text>`, the period index as serial number.
pub fn certificate_der(id: &P256PeerId, period: ValidityPeriod) -> Vec<u8> {
    let text = id.to_text();
    let mut tbs = vec![0xa0, 3, 2, 1, 2]; // v3
    tbs.extend_from_slice(&tlv(2, &serial_integer(period.0)));
    tbs.extend_from_slice(ED25519_ALGORITHM);
    tbs.extend_from_slice(&name(text.as_bytes()));
    let mut validity = der_time(period.begin());
    validity.extend_from_slice(&der_time(period.end()));
    tbs.extend_from_slice(&tlv(0x30, &validity));
    tbs.extend_from_slice(&name(JAM_COMMON_NAME.as_bytes()));

    // id-ecPublicKey, prime256v1, then an uncompressed point BIT STRING.
    let mut spki =
        b"\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
            .to_vec();
    let mut key_bits = vec![0];
    key_bits.extend_from_slice(&id.to_uncompressed_sec1());
    spki.extend_from_slice(&tlv(3, &key_bits));
    tbs.extend_from_slice(&tlv(0x30, &spki));

    // The only extension: a non-critical subjectAltName with the text peer ID.
    let names = tlv(0x30, &tlv(0x82, text.as_bytes()));
    let mut san = vec![6, 3, 0x55, 0x1d, 0x11];
    san.extend_from_slice(&tlv(4, &names));
    tbs.extend_from_slice(&tlv(0xa3, &tlv(0x30, &tlv(0x30, &san))));

    let mut certificate = tlv(0x30, &tbs);
    certificate.extend_from_slice(ED25519_ALGORITHM);
    certificate.extend_from_slice(&tlv(3, &[0; 65]));
    tlv(0x30, &certificate)
}

/// Hashes of [`certificate_der`] for the previous, current, and next ten-day period, in that order.
///
/// At Unix epoch the previous period saturates to zero. Dates beyond year 9999 saturate to
/// `9999-12-31 23:59:59`; integer arithmetic never wraps.
pub fn certificate_hashes(p256_id: &P256PeerId, now_unix_secs: u64) -> [[u8; 32]; 3] {
    let period = ValidityPeriod::from_unix_secs(now_unix_secs).0;
    [period.saturating_sub(1), period, period.saturating_add(1)]
        .map(|period| sha2::Sha256::digest(certificate_der(p256_id, ValidityPeriod(period))).into())
}

/// A distinguished name with one common name, a UTF8String, as rcgen writes it.
fn name(common_name: &[u8]) -> Vec<u8> {
    let mut attribute = vec![6, 3, 0x55, 4, 3]; // id-at-commonName
    attribute.extend_from_slice(&tlv(0x0c, common_name));
    tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)))
}

/// The content of a positive DER INTEGER, as rcgen writes a serial number: no leading zero
/// bytes, except one `0x00` when the high bit of the first byte is set.
fn serial_integer(serial: u64) -> Vec<u8> {
    let bytes = serial.to_be_bytes();
    let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let mut content = Vec::with_capacity(9);
    if bytes[first] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[first..]);
    content
}

fn der_time(dt: time::OffsetDateTime) -> Vec<u8> {
    let (tag, year) = if dt.year() < 2050 {
        (0x17, format!("{:02}", dt.year() % 100))
    } else {
        (0x18, format!("{:04}", dt.year()))
    };
    tlv(
        tag,
        format!(
            "{year}{:02}{:02}{:02}{:02}{:02}Z",
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
        .as_bytes(),
    )
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if let Ok(length) = u8::try_from(content.len())
        && length < 128
    {
        result.push(length);
    } else {
        let bytes = content.len().to_be_bytes();
        let significant = bytes.iter().skip_while(|&&byte| byte == 0);
        // A usize length has at most eight bytes on the supported targets.
        let length_bytes = significant.clone().fold(0u8, |n, _| n + 1);
        result.push(0x80 | length_bytes);
        result.extend(significant);
    }
    result.extend_from_slice(content);
    result
}

#[cfg(test)]
mod tests;
