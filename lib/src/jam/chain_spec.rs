// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! PolkaJam chain specifications and trusted checkpoints for GP 0.8.0.
//!
//! Hex strings may be bare (PolkaJam's export format) or prefixed with `0x`.
//! Full genesis state is accepted; only C(4), C(6), C(8), and C(11) are decoded.
//! This checks representations and slot consistency, not signatures, state-root
//! commitments, or checkpoint ancestry. The caller must trust the specification.

use super::{
    codec::{self, DecodeError},
    params::Params,
    types::{Ed25519Public, GenesisLightState, Header},
};
use alloc::{format, string::String, vec::Vec};
use core::net::IpAddr;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct JamChainSpec {
    id: String,
    params: Params,
    genesis_header: Header,
    genesis_light_state: GenesisLightState,
    checkpoint: Option<Checkpoint>,
    boot_nodes: Vec<BootNode>,
}

/// A trusted header and its post-state, not its prior state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub header: Header,
    pub state: GenesisLightState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootNode {
    /// Mandatory Ed25519 identity, as required by JIP-4 with JIPs PR #18.
    pub ed25519: Ed25519Public,
    /// Optional native `v`/`o` P-256 text, a local convention permitted by PR #18.
    /// The text encoding is checked here; light-base must validate the curve point before dialing.
    pub p256_id_text: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
}

/// Failures retain the JSON field/state key or bootnode index responsible.
#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    Hex {
        field: String,
        source: hex::FromHexError,
    },
    StateKeyLength {
        key: String,
        actual: usize,
    },
    Decode {
        field: String,
        source: DecodeError,
    },
    InvalidParameters {
        field: &'static str,
    },
    SlotMismatch {
        field: &'static str,
        header: u32,
        state: u32,
    },
    CheckpointBeforeGenesis {
        genesis: u32,
        checkpoint: u32,
    },
    BootNode {
        index: usize,
        source: BootNodeError,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootNodeError {
    Format,
    Address,
    PeerIdLength,
    MissingEd25519,
    DuplicateEd25519,
    DuplicateP256,
    PeerIdCharacter,
    PeerIdTrailingBits,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Decode { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Detects the top-level field, without requiring a valid JAM specification.
/// Invalid JSON and non-object roots return false; a null field still counts.
pub fn looks_like_jam_spec(json: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        protocol_parameters: serde::de::IgnoredAny,
    }
    json_object::<Probe>(json).is_ok_and(|probe| {
        let _ = probe.protocol_parameters;
        true
    })
}

// Derived struct deserializers also accept positional arrays. Chain specs are
// objects, so use map-only entry here while retaining serde's field diagnostics.
fn json_object<T: serde::de::DeserializeOwned>(json: &[u8]) -> Result<T, serde_json::Error> {
    struct Visitor<T>(core::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a chain specification object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let value = serde::Deserializer::deserialize_map(
        &mut deserializer,
        Visitor(core::marker::PhantomData),
    )?;
    deserializer.end()?;
    Ok(value)
}

#[derive(Deserialize)]
struct RawSpec {
    id: String,
    protocol_parameters: String,
    genesis_header: String,
    genesis_state: StateEntries,
    #[serde(default)]
    bootnodes: Vec<String>,
    checkpoint: Option<RawCheckpoint>,
}

#[derive(Deserialize)]
struct RawCheckpoint {
    header: String,
    state: RawCheckpointState,
}

#[derive(Deserialize)]
struct RawCheckpointState {
    safrole: String,
    entropy: String,
    active_validators: String,
    slot: String,
}

// A map would silently overwrite repeated JSON keys before codec validation.
struct StateEntries(Vec<(String, String)>);

impl<'de> Deserialize<'de> for StateEntries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StateEntries;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a genesis_state object of hex keys and values")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(StateEntries(entries))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

fn hex_bytes(field: &str, text: &str) -> Result<Vec<u8>, Error> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).map_err(|source| Error::Hex {
        field: field.into(),
        source,
    })
}

fn decode<T>(
    field: &str,
    bytes: &[u8],
    f: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
) -> Result<T, Error> {
    f(bytes).map_err(|source| Error::Decode {
        field: field.into(),
        source,
    })
}

fn state(
    params: &Params,
    field: &str,
    items: &[([u8; 31], Vec<u8>)],
) -> Result<GenesisLightState, Error> {
    let item = |index| {
        let mut matches = items
            .iter()
            .filter(|(key, _)| *key == codec::state_key(index));
        let (_, bytes) = matches.next().ok_or_else(|| Error::Decode {
            field: field.into(),
            source: DecodeError::MissingStateItem(index),
        })?;
        if matches.next().is_some() {
            return Err(Error::Decode {
                field: field.into(),
                source: DecodeError::DuplicateStateItem(index),
            });
        }
        Ok(bytes.as_slice())
    };
    Ok(GenesisLightState {
        safrole: decode(&format!("{field}.safrole"), item(4)?, |b| {
            super::types::SafroleState::decode(params, b)
        })?,
        entropy: decode(&format!("{field}.entropy"), item(6)?, codec::decode_entropy)?,
        active_validators: decode(&format!("{field}.active_validators"), item(8)?, |b| {
            codec::decode_active_validators(params, b)
        })?,
        slot: decode(&format!("{field}.slot"), item(11)?, codec::decode_slot)?,
    })
}

fn check_slot(
    field: &'static str,
    header: &Header,
    state: &GenesisLightState,
) -> Result<(), Error> {
    if header.slot != state.slot {
        return Err(Error::SlotMismatch {
            field,
            header: header.slot,
            state: state.slot,
        });
    }
    Ok(())
}

impl JamChainSpec {
    pub fn from_json_bytes(json: &[u8]) -> Result<Self, Error> {
        let raw: RawSpec = json_object(json).map_err(Error::Json)?;
        let params = decode(
            "protocol_parameters",
            &hex_bytes("protocol_parameters", &raw.protocol_parameters)?,
            Params::from_protocol_parameters,
        )?;
        // These quantities are divisors or index bounds in downstream Safrole.
        // Do not impose full-node configuration policy on other parameters.
        for (field, zero) in [
            ("epoch_len", params.epoch_len == 0),
            ("slot_seconds", params.slot_seconds == 0),
            ("max_validators", params.max_validators == 0),
        ] {
            if zero {
                return Err(Error::InvalidParameters { field });
            }
        }
        let genesis_header = decode(
            "genesis_header",
            &hex_bytes("genesis_header", &raw.genesis_header)?,
            |bytes| Header::decode(&params, bytes),
        )?;
        let mut items = Vec::new();
        for (key, value) in raw.genesis_state.0 {
            let bytes = hex_bytes(&format!("genesis_state key {key}"), &key)?;
            let actual = bytes.len();
            let decoded_key: [u8; 31] = bytes.try_into().map_err(|_| Error::StateKeyLength {
                key: key.clone(),
                actual,
            })?;
            let field = format!("genesis_state[{key}]");
            // Even unused entries must be well-formed hex, but their contents
            // need not be understood by a header-only client.
            let bytes = hex_bytes(&field, &value)?;
            if [4, 6, 8, 11]
                .into_iter()
                .any(|i| decoded_key == codec::state_key(i))
            {
                items.push((decoded_key, bytes));
            }
        }
        let genesis_light_state = state(&params, "genesis_state", &items)?;
        check_slot("genesis_state", &genesis_header, &genesis_light_state)?;
        let checkpoint = raw
            .checkpoint
            .map(|raw| {
                let header = decode(
                    "checkpoint.header",
                    &hex_bytes("checkpoint.header", &raw.header)?,
                    |bytes| Header::decode(&params, bytes),
                )?;
                let mut items = Vec::new();
                for (index, name, value) in [
                    (4, "safrole", raw.state.safrole),
                    (6, "entropy", raw.state.entropy),
                    (8, "active_validators", raw.state.active_validators),
                    (11, "slot", raw.state.slot),
                ] {
                    items.push((
                        codec::state_key(index),
                        hex_bytes(&format!("checkpoint.state.{name}"), &value)?,
                    ));
                }
                let state = state(&params, "checkpoint.state", &items)?;
                check_slot("checkpoint.state", &header, &state)?;
                if header.slot < genesis_header.slot {
                    return Err(Error::CheckpointBeforeGenesis {
                        genesis: genesis_header.slot,
                        checkpoint: header.slot,
                    });
                }
                Ok(Checkpoint { header, state })
            })
            .transpose()?;
        let boot_nodes = raw
            .bootnodes
            .iter()
            .enumerate()
            .map(|(index, text)| {
                parse_bootnode(text).map_err(|source| Error::BootNode { index, source })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id: raw.id,
            params,
            genesis_header,
            genesis_light_state,
            checkpoint,
            boot_nodes,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn params(&self) -> &Params {
        &self.params
    }
    pub fn genesis_header(&self) -> &Header {
        &self.genesis_header
    }
    pub fn genesis_light_state(&self) -> &GenesisLightState {
        &self.genesis_light_state
    }
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }
    pub fn boot_nodes(&self) -> impl Iterator<Item = BootNode> + '_ {
        self.boot_nodes.iter().cloned()
    }
}

fn parse_bootnode(text: &str) -> Result<BootNode, BootNodeError> {
    let (id, address) = text.split_once('@').ok_or(BootNodeError::Format)?;
    if id.is_empty() || address.contains('@') || text.chars().any(char::is_whitespace) {
        return Err(BootNodeError::Format);
    }
    let (host, port) = address.rsplit_once(':').ok_or(BootNodeError::Address)?;
    let host = if let Some(host) = host.strip_prefix('[') {
        host.strip_suffix(']').ok_or(BootNodeError::Address)?
    } else {
        if host.contains(':') {
            return Err(BootNodeError::Address);
        }
        host
    };
    let ip = host.parse().map_err(|_| BootNodeError::Address)?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BootNodeError::Address);
    }
    let port = port.parse().map_err(|_| BootNodeError::Address)?;
    let mut ed25519 = None;
    let mut p256_id_text = None;
    for identity in id.split('+') {
        match identity.as_bytes().first() {
            Some(b'e') => {
                if ed25519.is_some() {
                    return Err(BootNodeError::DuplicateEd25519);
                }
                ed25519 = Some(decode_identity(identity)?);
            }
            Some(b'v' | b'o') => {
                if p256_id_text.is_some() {
                    return Err(BootNodeError::DuplicateP256);
                }
                decode_identity(identity)?;
                p256_id_text = Some(identity.into());
            }
            None => return Err(BootNodeError::Format),
            // JIPs PR #18 requires clients to ignore formats they cannot interpret.
            Some(_) => {}
        }
    }
    Ok(BootNode {
        ed25519: ed25519.ok_or(BootNodeError::MissingEd25519)?,
        p256_id_text,
        ip,
        port,
    })
}

fn decode_identity(id: &str) -> Result<[u8; 32], BootNodeError> {
    // PolkaJam net/peer_id.rs: a prefix followed by 52 little-endian base32 digits.
    if id.len() != 53 {
        return Err(BootNodeError::PeerIdLength);
    }
    let mut peer_id = [0; 32];
    let mut accumulator = 0u16;
    let mut bits = 0;
    let mut output = peer_id.iter_mut();
    for digit in id.bytes().skip(1) {
        let value = match digit {
            b'a'..=b'z' => digit - b'a',
            b'2'..=b'7' => digit - b'2' + 26,
            _ => return Err(BootNodeError::PeerIdCharacter),
        };
        accumulator |= u16::from(value) << bits;
        bits += 5;
        if bits >= 8 {
            let byte = output.next().ok_or(BootNodeError::PeerIdLength)?;
            *byte = accumulator.to_le_bytes()[0];
            accumulator >>= 8;
            bits -= 8;
        }
    }
    if accumulator != 0 {
        return Err(BootNodeError::PeerIdTrailingBits);
    }
    Ok(peer_id)
}

#[cfg(test)]
mod tests {
    use super::super::types::{SafroleState, SealingSequence, Ticket, ValidatorKey};
    use super::*;
    use alloc::vec;
    use serde_json::{Value, json};

    fn parameters() -> Vec<u8> {
        let mut bytes = vec![0; 122];
        bytes[24..26].copy_from_slice(&2u16.to_le_bytes());
        bytes[30..34].copy_from_slice(&3u32.to_le_bytes());
        bytes[80..82].copy_from_slice(&6u16.to_le_bytes());
        bytes
    }

    fn sample(slot: u32, tickets: bool) -> (Value, Header, GenesisLightState) {
        let bytes = parameters();
        let params = Params::from_protocol_parameters(&bytes).unwrap();
        let validator = ValidatorKey {
            bandersnatch: [1; 32],
            ed25519: [2; 32],
            bls: [3; 144],
            metadata: [4; 128],
        };
        let ticket = Ticket {
            id: [9; 32],
            attempt: 1,
        };
        let state = GenesisLightState {
            safrole: SafroleState {
                pending_validators: vec![validator.clone(); 6],
                epoch_root: [5; 144],
                sealing: if tickets {
                    SealingSequence::Tickets(vec![ticket.clone(); 3])
                } else {
                    SealingSequence::Keys(vec![[6; 32]; 3])
                },
                ticket_accumulator: vec![ticket],
            },
            entropy: [[7; 32]; 4],
            active_validators: vec![validator; 6],
            slot,
        };
        let header = Header {
            parent: [8; 32],
            prior_state_root: [9; 32],
            extrinsic_hash: [10; 32],
            slot,
            epoch_mark: None,
            tickets_mark: None,
            author_index: u16::MAX,
            entropy_source: [11; 96],
            offenders_mark: vec![],
            seal: [12; 96],
        };
        let mut entries = serde_json::Map::new();
        for (index, bytes) in state_bytes(&state, &params) {
            entries.insert(
                hex::encode(codec::state_key(index)),
                json!(hex::encode(bytes)),
            );
        }
        (
            json!({"id":"test", "protocol_parameters":hex::encode(bytes), "genesis_header":hex::encode(header.encode(&params)), "genesis_state":entries}),
            header,
            state,
        )
    }

    fn state_bytes(state: &GenesisLightState, params: &Params) -> [(u8, Vec<u8>); 4] {
        [
            (4, state.safrole.encode(params)),
            (6, codec::encode_entropy(&state.entropy)),
            (8, codec::encode_active_validators(&state.active_validators)),
            (11, codec::encode_slot(state.slot).to_vec()),
        ]
    }

    fn parse(value: &Value) -> Result<JamChainSpec, Error> {
        JamChainSpec::from_json_bytes(&serde_json::to_vec(value).unwrap())
    }

    fn checkpoint(spec: &mut Value, slot: u32) {
        let (raw, header, state) = sample(slot, true);
        let params = Params::from_protocol_parameters(&parameters()).unwrap();
        spec["checkpoint"] = json!({"header":raw["genesis_header"], "state": {
            "safrole":hex::encode(state.safrole.encode(&params)), "entropy":hex::encode(codec::encode_entropy(&state.entropy)),
            "active_validators":hex::encode(codec::encode_active_validators(&state.active_validators)), "slot":hex::encode(header.slot.to_le_bytes())
        }});
    }

    #[test]
    fn positive_full_state_and_hex_forms() {
        for tickets in [false, true] {
            let (mut raw, header, state) = sample(42, tickets);
            raw["unknown_extension"] = json!({"allowed":true});
            raw["genesis_state"][hex::encode(codec::state_key(9))] = json!("0xdeadBEEF");
            for prefixed in [false, true] {
                if prefixed {
                    for field in ["protocol_parameters", "genesis_header"] {
                        raw[field] =
                            json!(format!("0x{}", raw[field].as_str().unwrap().to_uppercase()));
                    }
                    let entries = raw["genesis_state"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| {
                            (
                                format!("0x{}", k.to_uppercase()),
                                json!(format!(
                                    "0x{}",
                                    v.as_str().unwrap().trim_start_matches("0x").to_uppercase()
                                )),
                            )
                        })
                        .collect();
                    raw["genesis_state"] = Value::Object(entries);
                }
                let parsed = parse(&raw).unwrap();
                assert_eq!(parsed.id(), "test");
                assert_eq!(
                    parsed.params(),
                    &Params::from_protocol_parameters(&parameters()).unwrap()
                );
                assert_eq!(parsed.genesis_header(), &header);
                assert_eq!(parsed.genesis_light_state(), &state);
                assert!(parsed.checkpoint().is_none());
                assert_eq!(parsed.boot_nodes().count(), 0);
            }
        }
    }

    #[test]
    fn detection_and_json_errors() {
        for input in [
            r#"{"protocol_parameters":null}"#,
            r#"{"protocol_parameters":123,"extra":[]}"#,
        ] {
            assert!(looks_like_jam_spec(input.as_bytes()));
        }
        for input in [
            "null",
            "[]",
            "[0]",
            "{}",
            "{",
            r#"{"nested":{"protocol_parameters":""}}"#,
            r#"{"protocol_parameters":0} trailing"#,
        ] {
            assert!(!looks_like_jam_spec(input.as_bytes()));
        }
        let (raw, _, _) = sample(0, false);
        for field in [
            "id",
            "protocol_parameters",
            "genesis_header",
            "genesis_state",
        ] {
            let mut missing = raw.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(matches!(parse(&missing), Err(Error::Json(_))));
            for wrong in [json!(null), json!(42), json!([])] {
                let mut invalid = raw.clone();
                invalid[field] = wrong;
                assert!(matches!(parse(&invalid), Err(Error::Json(_))));
            }
        }
        for wrong in [json!(null), json!(42), json!([1])] {
            let mut raw = raw.clone();
            raw["bootnodes"] = wrong;
            assert!(matches!(parse(&raw), Err(Error::Json(_))));
        }
        let encoded = serde_json::to_string(&raw).unwrap();
        let duplicate = encoded.replacen('{', "{\"id\":\"duplicate\",", 1);
        assert!(matches!(
            JamChainSpec::from_json_bytes(duplicate.as_bytes()),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn strict_hex_and_binary_errors() {
        for field in ["protocol_parameters", "genesis_header"] {
            for invalid in ["0", "0x0", "0X00", " 00", "00 ", "gg", "é", "0x0x00"] {
                let (mut raw, _, _) = sample(0, false);
                raw[field] = json!(invalid);
                assert!(matches!(parse(&raw), Err(Error::Hex { field: f, .. }) if f == field));
            }
            for invalid in ["", "0x", "00"] {
                let (mut raw, _, _) = sample(0, false);
                raw[field] = json!(invalid);
                assert!(matches!(parse(&raw), Err(Error::Decode { field: f, .. }) if f == field));
            }
            let (mut raw, _, _) = sample(0, false);
            raw[field] = json!(format!("{}00", raw[field].as_str().unwrap()));
            assert!(matches!(
                parse(&raw),
                Err(Error::Decode {
                    source: DecodeError::TrailingBytes,
                    ..
                })
            ));
        }
        for (offset, len, field) in [(30, 4, "epoch_len"), (80, 2, "slot_seconds")] {
            let (mut raw, _, _) = sample(0, false);
            let mut bytes = parameters();
            bytes[offset..offset + len].fill(0);
            raw["protocol_parameters"] = json!(hex::encode(bytes));
            assert!(
                matches!(parse(&raw), Err(Error::InvalidParameters { field: f }) if f == field)
            );
        }
    }

    #[test]
    fn required_state_missing_duplicates_and_malformed() {
        for (index, name) in [
            (4, "safrole"),
            (6, "entropy"),
            (8, "active_validators"),
            (11, "slot"),
        ] {
            let key = hex::encode(codec::state_key(index));
            let (raw, _, _) = sample(0, false);
            let mut missing = raw.clone();
            missing["genesis_state"]
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(
                matches!(parse(&missing), Err(Error::Decode { source: DecodeError::MissingStateItem(i), .. }) if i == index)
            );
            for duplicate_key in [key.clone(), format!("0x{}", key.to_uppercase())] {
                let json = serde_json::to_string(&raw).unwrap();
                let duplicate = json.replacen(
                    &format!("\"{key}\":"),
                    &format!(
                        "\"{duplicate_key}\":{},\"{key}\":",
                        raw["genesis_state"][&key]
                    ),
                    1,
                );
                assert!(
                    matches!(JamChainSpec::from_json_bytes(duplicate.as_bytes()), Err(Error::Decode { source: DecodeError::DuplicateStateItem(i), .. }) if i == index)
                );
            }
            for invalid in [
                "".into(),
                format!("{}00", raw["genesis_state"][&key].as_str().unwrap()),
            ] {
                let mut malformed = raw.clone();
                malformed["genesis_state"][&key] = json!(invalid);
                assert!(
                    matches!(parse(&malformed), Err(Error::Decode { field, .. }) if field == format!("genesis_state.{name}"))
                );
            }
            let mut malformed = raw.clone();
            malformed["genesis_state"][&key] = json!("zz");
            assert!(matches!(parse(&malformed), Err(Error::Hex { .. })));
        }
        for key in ["00", "", &"00".repeat(32)] {
            let (mut raw, _, _) = sample(0, false);
            raw["genesis_state"][key] = json!("");
            assert!(matches!(parse(&raw), Err(Error::StateKeyLength { .. })));
        }
    }

    #[test]
    fn checkpoint_validation_and_slot_consistency() {
        for slot in [5, 6, u32::MAX] {
            let (mut raw, _, _) = sample(5, false);
            checkpoint(&mut raw, slot);
            let parsed = parse(&raw).unwrap();
            let checkpoint = parsed.checkpoint().unwrap();
            assert_eq!(checkpoint.header.slot, slot);
            assert_eq!(checkpoint.state.slot, slot);
        }
        let (mut raw, _, _) = sample(5, false);
        checkpoint(&mut raw, 4);
        assert!(matches!(
            parse(&raw),
            Err(Error::CheckpointBeforeGenesis {
                genesis: 5,
                checkpoint: 4
            })
        ));
        checkpoint(&mut raw, 6);
        raw["checkpoint"]["state"]["slot"] = json!("07000000");
        assert!(matches!(
            parse(&raw),
            Err(Error::SlotMismatch {
                field: "checkpoint.state",
                ..
            })
        ));
        raw.as_object_mut().unwrap().remove("checkpoint");
        raw["genesis_state"][hex::encode(codec::state_key(11))] = json!("07000000");
        assert!(matches!(
            parse(&raw),
            Err(Error::SlotMismatch {
                field: "genesis_state",
                ..
            })
        ));
        for field in ["safrole", "entropy", "active_validators", "slot"] {
            let (mut raw, _, _) = sample(0, false);
            checkpoint(&mut raw, 0);
            let mut missing = raw.clone();
            missing["checkpoint"]["state"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(matches!(parse(&missing), Err(Error::Json(_))));
            raw["checkpoint"]["state"][field] = json!("");
            assert!(
                matches!(parse(&raw), Err(Error::Decode { field: f, .. }) if f == format!("checkpoint.state.{field}"))
            );
        }
        let (mut raw, _, _) = sample(0, false);
        checkpoint(&mut raw, 0);
        raw["checkpoint"]["header"] = json!("00");
        assert!(
            matches!(parse(&raw), Err(Error::Decode { field, .. }) if field == "checkpoint.header")
        );
    }

    #[test]
    fn bootnode_identities_and_addresses() {
        assert_eq!(
            parse_bootnode(&format!("e{}@2001:db8::1:65535", "a".repeat(52))),
            Err(BootNodeError::Address)
        );
        // Little-endian base32 for 256 one bits ends in 'b', not RFC4648's 'q'.
        let ed = format!("e{}b", "7".repeat(51));
        for (address, ip, port) in [
            ("127.0.0.1:40000", "127.0.0.1", 40000),
            ("[127.0.0.1]:40000", "127.0.0.1", 40000),
            ("[2001:db8::1]:65535", "2001:db8::1", 65535),
        ] {
            let expected = BootNode {
                ed25519: [255; 32],
                p256_id_text: None,
                ip: ip.parse().unwrap(),
                port,
            };
            for identities in [ed.clone(), format!("x!+{ed}+future:unknown")] {
                assert_eq!(
                    parse_bootnode(&format!("{identities}@{address}")),
                    Ok(expected.clone())
                );
            }
            for prefix in ['v', 'o'] {
                let p256 = format!("{prefix}{}", "a".repeat(52));
                for identities in [format!("{ed}+{p256}"), format!("{p256}+x!+{ed}")] {
                    assert_eq!(
                        parse_bootnode(&format!("{identities}@{address}")),
                        Ok(BootNode {
                            p256_id_text: Some(p256.clone()),
                            ..expected.clone()
                        })
                    );
                }
            }
        }
        let (mut raw, _, _) = sample(0, false);
        raw["bootnodes"] = json!([
            format!("{ed}+v{}@127.0.0.1:1", "a".repeat(52)),
            format!("{ed}@127.0.0.1:1")
        ]);
        assert_eq!(parse(&raw).unwrap().boot_nodes().count(), 2);
    }

    #[test]
    fn bootnode_errors_name_the_entry() {
        let ed = format!("e{}", "a".repeat(52));
        let even = format!("v{}", "a".repeat(52));
        let odd = format!("o{}", "a".repeat(52));
        let mut invalid = vec![
            (even.clone(), BootNodeError::MissingEd25519),
            ("future!".into(), BootNodeError::MissingEd25519),
            (format!("{ed}+{ed}"), BootNodeError::DuplicateEd25519),
            (format!("{ed}+{even}+{odd}"), BootNodeError::DuplicateP256),
            (format!("{ed}+{even}+{even}"), BootNodeError::DuplicateP256),
            (format!("{ed}+"), BootNodeError::Format),
            (format!("+{ed}"), BootNodeError::Format),
            (format!("{ed}++x"), BootNodeError::Format),
        ];
        for prefix in ['e', 'v', 'o'] {
            for (body, error) in [
                ("a".repeat(51), BootNodeError::PeerIdLength),
                ("a".repeat(53), BootNodeError::PeerIdLength),
                (
                    format!("{}!", "a".repeat(51)),
                    BootNodeError::PeerIdCharacter,
                ),
                (
                    format!("{}A", "a".repeat(51)),
                    BootNodeError::PeerIdCharacter,
                ),
                (
                    format!("{}c", "a".repeat(51)),
                    BootNodeError::PeerIdTrailingBits,
                ),
            ] {
                let identity = format!("{prefix}{body}");
                invalid.push((
                    if prefix == 'e' {
                        identity
                    } else {
                        format!("{ed}+{identity}")
                    },
                    error,
                ));
            }
        }
        let (mut raw, _, _) = sample(0, false);
        for (identities, expected) in invalid {
            raw["bootnodes"] = json!([
                format!("{ed}@127.0.0.1:1"),
                format!("{identities}@127.0.0.1:1")
            ]);
            assert!(
                matches!(parse(&raw), Err(Error::BootNode { index: 1, source }) if source == expected),
                "{identities}"
            );
        }
        for address in [
            "localhost:1",
            "127.0.0.1:65536",
            "127.0.0.1",
            "[::1:1",
            "::1]:1",
            "127.0.0.1:+1",
            "127.0.0.1:",
        ] {
            assert_eq!(
                parse_bootnode(&format!("{ed}@{address}")),
                Err(BootNodeError::Address)
            );
        }
        for text in [
            "".into(),
            format!("{ed}@@127.0.0.1:1"),
            format!("{ed} @127.0.0.1:1"),
        ] {
            assert_eq!(parse_bootnode(&text), Err(BootNodeError::Format));
        }
    }

    #[test]
    #[ignore = "requires external A5 fixtures; set JAM_A5_FIXTURES or use the planning directory"]
    fn external_polkajam_fixture() {
        let root = std::env::var("JAM_A5_FIXTURES").unwrap_or_else(|_| {
            "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into()
        });
        let spec = JamChainSpec::from_json_bytes(
            &std::fs::read(format!("{root}/chain-spec.polkajam.json")).unwrap(),
        )
        .unwrap();
        let expected: Value =
            serde_json::from_slice(&std::fs::read(format!("{root}/genesis-state.json")).unwrap())
                .unwrap();
        assert_eq!(
            hex::encode(spec.genesis_header().hash(spec.params())),
            expected["header_hash"]
        );
        assert_eq!(
            hex::encode(spec.genesis_header().encode(spec.params())),
            expected["header_hex"]
        );
        assert_eq!(
            spec.params(),
            &Params {
                deposit_per_item: 10,
                deposit_per_byte: 1,
                deposit_per_account: 100,
                core_count: 2,
                min_turnaround_period: 32,
                epoch_len: 12,
                max_accumulate_gas: 10_000_000,
                max_is_authorized_gas: 50_000_000,
                max_refine_gas: 1_000_000_000,
                block_gas_limit: 20_000_000,
                recent_block_count: 8,
                max_work_items: 16,
                max_dependencies: 8,
                max_tickets_per_ext: 3,
                max_lookup_anchor_age: 24,
                auth_window: 8,
                slot_seconds: 6,
                auth_queue_len: 80,
                rotation_period: 4,
                max_extrinsics: 128,
                availability_timeout: 5,
                max_validators: 6,
                max_authorizer_code_size: 64_000,
                max_input: 13_791_360,
                max_service_code_size: 4_000_000,
                max_imports: 3072,
                max_report_elective_data: 49_152,
                transfer_memo_size: 128,
                max_exports: 3072,
                epoch_tail_start: 10,
            }
        );
        for (index, bytes) in state_bytes(spec.genesis_light_state(), spec.params()) {
            let item = expected["light_state"]["state_items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["index"] == index)
                .unwrap();
            assert_eq!(hex::encode(codec::state_key(index)), item["key_hex"]);
            assert_eq!(hex::encode(bytes), item["value_hex"]);
        }
        assert_eq!(
            u64::from(spec.genesis_light_state().slot),
            expected["light_state"]["slot"].as_u64().unwrap()
        );
    }
}
