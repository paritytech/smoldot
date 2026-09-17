// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Typed access to the shared captured CE128 vectors. Compiled only for tests.

use super::Params;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Deserializer, de::Error as _};

#[derive(Deserialize)]
pub(crate) struct Ce128 {
    #[serde(rename = "protocol_parameters_hex", deserialize_with = "parameters")]
    pub params: Params,
    #[serde(rename = "request_frame_hex", deserialize_with = "hex_bytes")]
    pub request_frame: Vec<u8>,
    #[serde(rename = "response_frame_hex", deserialize_with = "hex_bytes")]
    pub wire: Vec<u8>,
    pub blocks: Vec<BlockBoundary>,
    pub resets: Vec<Reset>,
}

#[derive(Deserialize)]
pub(crate) struct BlockBoundary {
    pub start: usize,
    pub body_start: usize,
    pub end: usize,
    pub header_hash: String,
    pub parent_hash: String,
    pub slot: u32,
    pub ticket_count: u8,
}

#[derive(Deserialize)]
pub(crate) struct Reset {
    pub name: String,
    #[serde(rename = "request_frame_hex", deserialize_with = "hex_bytes")]
    pub request_frame: Vec<u8>,
    pub reset: bool,
    pub source: String,
    #[serde(rename = "streamErrorCode")]
    pub stream_error_code: u32,
    pub response_frame_hex: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Corruption {
    Truncated,
    TooManyTickets,
}

impl Ce128 {
    pub fn payload(&self) -> &[u8] {
        &self.wire[4..]
    }

    pub fn corrupted_payload(&self, block: usize, corruption: Corruption) -> Vec<u8> {
        let boundary = &self.blocks[block];
        let mut payload = self.payload().to_vec();
        match corruption {
            Corruption::Truncated => payload.truncate(boundary.end - 1),
            // The captured tiny network permits at most three tickets.
            Corruption::TooManyTickets => payload[boundary.body_start] = 4,
        }
        payload
    }
}

#[rstest::fixture]
pub(crate) fn captured_ce128() -> Ce128 {
    let capture: Ce128 =
        serde_json::from_str(include_str!("../finality/fixtures/polkajam-ce128.json")).unwrap();
    for frame in [&capture.wire, &capture.request_frame] {
        assert_eq!(
            usize::try_from(u32::from_le_bytes(frame[..4].try_into().unwrap())).unwrap(),
            frame.len() - 4
        );
    }
    capture
}

fn hex_bytes<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
    hex::decode(String::deserialize(input)?).map_err(D::Error::custom)
}

fn parameters<'de, D: Deserializer<'de>>(input: D) -> Result<Params, D::Error> {
    Params::from_protocol_parameters(&hex_bytes(input)?).map_err(D::Error::custom)
}
