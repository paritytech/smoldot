// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Encoding and decoding of statements for the Statement Store protocol.
//!
//! Statements are encoded as `Vec<Field>` where each field has a discriminant byte
//! followed by field-specific data. Fields must appear in ascending order by discriminant.

use alloc::vec::Vec;

/// Maximum number of topics per statement.
pub const MAX_TOPICS: usize = 4;

/// `MatchAny` allows to provide a list of topics match against. This is the maximum number of
/// topics allowed.
pub const MAX_ANY_TOPICS: usize = 128;

/// Maximum number of statements allowed in a single notification.
const MAX_STATEMENTS_PER_NOTIFICATION: usize = 10_000;

const FIELD_PROOF: u8 = 0;
const FIELD_DECRYPTION_KEY: u8 = 1;
const FIELD_EXPIRY: u8 = 2;
const FIELD_CHANNEL: u8 = 3;
const FIELD_TOPIC_START: u8 = 4;
const FIELD_TOPIC_END: u8 = FIELD_TOPIC_START + MAX_TOPICS as u8 - 1;
const FIELD_DATA: u8 = 8;

const PROOF_SR25519: u8 = 0;
const PROOF_ED25519: u8 = 1;
const PROOF_SECP256K1_ECDSA: u8 = 2;
const PROOF_ON_CHAIN: u8 = 3;

/// Statement topic (32 bytes).
pub type Topic = [u8; 32];

/// Filter for subscribing to statements based on topics.
///
/// JSON format is compatible with polkadot-sdk's `TopicFilter`:
/// ```json
/// "any"
/// {"matchAll": ["0x0123...abcd", "0x5678...efgh"]}
/// {"matchAny": ["0x0123...abcd"]}
/// ```
#[derive(Debug, Clone)]
pub enum TopicFilter {
    /// Matches all statements regardless of topics.
    Any,
    /// Matches only statements that include ALL of the given topics.
    /// Up to [`MAX_TOPICS`] (4) topics can be provided.
    MatchAll(Vec<Topic>),
    /// Matches statements that include ANY of the given topics.
    /// Up to [`MAX_ANY_TOPICS`] (128) topics can be provided.
    /// An empty vector means no statements will be accepted.
    MatchAny(Vec<Topic>),
}

impl serde::Serialize for TopicFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        fn topics_to_hex(topics: &[Topic]) -> Vec<alloc::string::String> {
            topics
                .iter()
                .map(|t| alloc::format!("0x{}", hex::encode(t)))
                .collect()
        }

        use serde::ser::SerializeMap;

        let (key, topics) = match self {
            TopicFilter::Any => return serializer.serialize_str("any"),
            TopicFilter::MatchAll(topics) => ("matchAll", topics),
            TopicFilter::MatchAny(topics) => ("matchAny", topics),
        };

        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(key, &topics_to_hex(topics))?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for TopicFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        struct TopicFilterVisitor;

        impl<'de> serde::de::Visitor<'de> for TopicFilterVisitor {
            type Value = TopicFilter;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str(r#""any" or {"matchAll": [...]} or {"matchAny": [...]}"#)
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<TopicFilter, E> {
                match value {
                    "any" => Ok(TopicFilter::Any),
                    other => Err(E::custom(alloc::format!(
                        "unknown filter type: {other}, expected \"any\""
                    ))),
                }
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<TopicFilter, A::Error> {
                let key: alloc::string::String = map
                    .next_key()?
                    .ok_or_else(|| A::Error::custom("empty object"))?;
                let hex_topics: alloc::vec::Vec<alloc::string::String> = map.next_value()?;
                let topics: Vec<Topic> = hex_topics
                    .iter()
                    .map(|s| {
                        let s = s.strip_prefix("0x").unwrap_or(s);
                        let bytes =
                            hex::decode(s).map_err(|e| A::Error::custom(alloc::format!("{e}")))?;
                        <[u8; 32]>::try_from(bytes.as_slice())
                            .map_err(|_| A::Error::custom("topic must be exactly 32 bytes"))
                    })
                    .collect::<Result<_, _>>()?;

                match key.as_str() {
                    "matchAll" => TopicFilter::match_all(topics).map_err(A::Error::custom),
                    "matchAny" => TopicFilter::match_any(topics).map_err(A::Error::custom),
                    other => Err(A::Error::custom(alloc::format!(
                        "unknown filter key: {other}, expected \"matchAll\" or \"matchAny\""
                    ))),
                }
            }
        }

        deserializer.deserialize_any(TopicFilterVisitor)
    }
}

impl TopicFilter {
    pub fn match_all(topics: Vec<Topic>) -> Result<Self, alloc::string::String> {
        if topics.len() > MAX_TOPICS {
            return Err(alloc::format!(
                "Too many topics for MatchAll: got {}, max {}",
                topics.len(),
                MAX_TOPICS
            ));
        }
        Ok(TopicFilter::MatchAll(topics))
    }

    pub fn match_any(topics: Vec<Topic>) -> Result<Self, alloc::string::String> {
        if topics.len() > MAX_ANY_TOPICS {
            return Err(alloc::format!(
                "Too many topics for MatchAny: got {}, max {}",
                topics.len(),
                MAX_ANY_TOPICS
            ));
        }
        Ok(TopicFilter::MatchAny(topics))
    }

    /// Returns `true` if the given statement topics match this filter.
    pub fn matches(&self, statement_topics: &[Topic]) -> bool {
        match self {
            TopicFilter::Any => true,
            TopicFilter::MatchAny(filter_topics) => {
                if filter_topics.is_empty() {
                    return false;
                }
                statement_topics.iter().any(|t| filter_topics.contains(t))
            }
            TopicFilter::MatchAll(filter_topics) => {
                filter_topics.iter().all(|t| statement_topics.contains(t))
            }
        }
    }
}

/// Decryption key identifier (32 bytes).
pub type DecryptionKey = [u8; 32];

/// Channel identifier (32 bytes).
pub type Channel = [u8; 32];

/// Account identifier (32 bytes).
pub type AccountId = [u8; 32];

/// Block hash (32 bytes).
pub type BlockHash = [u8; 32];

/// A decoded statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Authentication proof for the statement.
    pub proof: Option<Proof>,
    /// Identifier for the key that the data field may be decrypted with.
    pub decryption_key: Option<DecryptionKey>,
    /// Statement expiry/priority.
    ///
    /// The most significant 32 bits represents the expiration timestamp (in seconds since
    /// UNIX epoch) after which the statement gets removed.
    /// The lower 32 bits represents an arbitrary sequence number used to order statements
    /// with the same expiration time.
    ///
    /// Higher values indicate a higher priority.
    pub expiry: u64,
    /// Account channel. Only one message per (account, channel) pair is allowed.
    pub channel: Option<Channel>,
    /// Statement topics (0 to 4).
    pub topics: Vec<Topic>,
    /// Additional data.
    pub data: Option<Vec<u8>>,
}

/// Statement proof variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// Sr25519 signature proof.
    Sr25519 {
        /// The signature (64 bytes).
        signature: [u8; 64],
        /// The signer's public key (32 bytes).
        signer: [u8; 32],
    },
    /// Ed25519 signature proof.
    Ed25519 {
        /// The signature (64 bytes).
        signature: [u8; 64],
        /// The signer's public key (32 bytes).
        signer: [u8; 32],
    },
    /// Secp256k1 ECDSA signature proof.
    Secp256k1Ecdsa {
        /// The signature (65 bytes).
        signature: [u8; 65],
        /// The signer's public key (33 bytes).
        signer: [u8; 33],
    },
    /// On-chain event proof.
    OnChain {
        /// Account identifier associated with the event.
        who: AccountId,
        /// Hash of block that contains the event.
        block_hash: BlockHash,
        /// Index of the event in the event list.
        event_index: u64,
    },
}

pub fn statement_hash(statement_bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], statement_bytes).as_bytes())
        .expect("blake2b output is 32 bytes; qed")
}

/// Decodes a statement.
pub fn decode_statement(bytes: &[u8]) -> Result<Statement, DecodeStatementNotificationError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming::<_, nom::error::Error<&[u8]>, _>(
            nom::combinator::complete(statement_parser),
        ),
        bytes,
    ) {
        Ok((_, s)) => Ok(s),
        Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
            Err(DecodeStatementNotificationError(e.code))
        }
        Err(nom::Err::Incomplete(_)) => {
            Err(DecodeStatementNotificationError(nom::error::ErrorKind::Eof))
        }
    }
}

pub fn decode_statement_notification(
    scale_encoded: &[u8],
) -> Result<Vec<([u8; 32], Statement)>, DecodeStatementNotificationError> {
    let (mut remaining, count) = crate::util::nom_scale_compact_usize(scale_encoded).map_err(
        |_: nom::Err<nom::error::Error<&[u8]>>| {
            DecodeStatementNotificationError(nom::error::ErrorKind::Fail)
        },
    )?;

    if count > MAX_STATEMENTS_PER_NOTIFICATION {
        return Err(DecodeStatementNotificationError(
            nom::error::ErrorKind::TooLarge,
        ));
    }

    let mut statements = Vec::with_capacity(count);
    for _ in 0..count {
        let start = remaining;
        let (rest, statement) = statement_parser(remaining).map_err(|e| match e {
            nom::Err::Error(e) | nom::Err::Failure(e) => DecodeStatementNotificationError(e.code),
            nom::Err::Incomplete(_) => DecodeStatementNotificationError(nom::error::ErrorKind::Eof),
        })?;
        let raw = &start[..start.len() - rest.len()];
        let hash = statement_hash(raw);
        statements.push((hash, statement));
        remaining = rest;
    }

    if !remaining.is_empty() {
        return Err(DecodeStatementNotificationError(
            nom::error::ErrorKind::NonEmpty,
        ));
    }

    Ok(statements)
}

/// Error when decoding a statement notification.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
#[display("Failed to decode statement notification {_0:?}")]
pub struct DecodeStatementNotificationError(#[error(not(source))] nom::error::ErrorKind);

/// Error when encoding a statement.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum EncodeStatementError {
    /// Too many topics in statement.
    #[display("Too many topics: got {got}, max {max}")]
    TooManyTopics {
        /// Number of topics provided.
        got: usize,
        /// Maximum allowed topics.
        max: usize,
    },
}

/// Encodes a single statement.
pub fn encode_statement(statement: &Statement) -> Result<Vec<u8>, EncodeStatementError> {
    let mut out = Vec::new();
    encode_statement_into(statement, &mut out)?;
    Ok(out)
}

fn encode_statement_into(
    statement: &Statement,
    out: &mut Vec<u8>,
) -> Result<(), EncodeStatementError> {
    if statement.topics.len() > MAX_TOPICS {
        return Err(EncodeStatementError::TooManyTopics {
            got: statement.topics.len(),
            max: MAX_TOPICS,
        });
    }

    let num_fields = statement.proof.is_some() as usize
        + statement.decryption_key.is_some() as usize
        + 1 // expiry is always present
        + statement.channel.is_some() as usize
        + statement.topics.len()
        + statement.data.is_some() as usize;

    out.extend_from_slice(crate::util::encode_scale_compact_usize(num_fields).as_ref());

    if let Some(proof) = &statement.proof {
        out.push(FIELD_PROOF);
        encode_proof_into(proof, out);
    }

    if let Some(key) = &statement.decryption_key {
        out.push(FIELD_DECRYPTION_KEY);
        out.extend_from_slice(key);
    }

    out.push(FIELD_EXPIRY);
    out.extend_from_slice(&statement.expiry.to_le_bytes());

    if let Some(channel) = &statement.channel {
        out.push(FIELD_CHANNEL);
        out.extend_from_slice(channel);
    }

    for (i, topic) in statement.topics.iter().enumerate() {
        out.push(FIELD_TOPIC_START + i as u8);
        out.extend_from_slice(topic);
    }

    if let Some(data) = &statement.data {
        out.push(FIELD_DATA);
        out.extend_from_slice(crate::util::encode_scale_compact_usize(data.len()).as_ref());
        out.extend_from_slice(data);
    }

    Ok(())
}

fn encode_proof_into(proof: &Proof, out: &mut Vec<u8>) {
    match proof {
        Proof::Sr25519 { signature, signer } => {
            out.push(PROOF_SR25519);
            out.extend_from_slice(signature.as_slice());
            out.extend_from_slice(signer.as_slice());
        }
        Proof::Ed25519 { signature, signer } => {
            out.push(PROOF_ED25519);
            out.extend_from_slice(signature.as_slice());
            out.extend_from_slice(signer.as_slice());
        }
        Proof::Secp256k1Ecdsa { signature, signer } => {
            out.push(PROOF_SECP256K1_ECDSA);
            out.extend_from_slice(signature.as_slice());
            out.extend_from_slice(signer.as_slice());
        }
        Proof::OnChain {
            who,
            block_hash,
            event_index,
        } => {
            out.push(PROOF_ON_CHAIN);
            out.extend_from_slice(who.as_slice());
            out.extend_from_slice(block_hash.as_slice());
            out.extend_from_slice(&event_index.to_le_bytes());
        }
    }
}

// Nom parsers

fn statement_parser(input: &[u8]) -> nom::IResult<&[u8], Statement> {
    let (input, num_fields) = crate::util::nom_scale_compact_usize(input)?;
    fields_parser(num_fields)(input)
}

fn fields_parser(num_fields: usize) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Statement> {
    move |mut input: &[u8]| {
        let mut proof = None;
        let mut decryption_key = None;
        let mut expiry = None;
        let mut channel = None;
        let mut topics = Vec::new();
        let mut data = None;

        let mut last_tag: Option<u8> = None;

        for _ in 0..num_fields {
            let (rest, tag) = nom::number::streaming::u8(input)?;

            if let Some(lt) = last_tag {
                if tag <= lt {
                    return Err(nom::Err::Failure(nom::error::make_error(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            }
            last_tag = Some(tag);

            let rest = match tag {
                FIELD_PROOF => {
                    let (rest, p) = proof_parser(rest)?;
                    proof = Some(p);
                    rest
                }
                FIELD_DECRYPTION_KEY => {
                    let (rest, key) = nom::bytes::streaming::take(32u32)(rest)?;
                    decryption_key =
                        Some(<[u8; 32]>::try_from(key).expect("take(32) guarantees 32 bytes; qed"));
                    rest
                }
                FIELD_EXPIRY => {
                    let (rest, exp) = nom::number::streaming::le_u64(rest)?;
                    expiry = Some(exp);
                    rest
                }
                FIELD_CHANNEL => {
                    let (rest, ch) = nom::bytes::streaming::take(32u32)(rest)?;
                    channel =
                        Some(<[u8; 32]>::try_from(ch).expect("take(32) guarantees 32 bytes; qed"));
                    rest
                }
                FIELD_TOPIC_START..=FIELD_TOPIC_END => {
                    let topic_index = (tag - FIELD_TOPIC_START) as usize;
                    if topic_index != topics.len() {
                        return Err(nom::Err::Failure(nom::error::make_error(
                            input,
                            nom::error::ErrorKind::Verify,
                        )));
                    }
                    let (rest, topic) = nom::bytes::streaming::take(32u32)(rest)?;
                    topics.push(
                        <[u8; 32]>::try_from(topic).expect("take(32) guarantees 32 bytes; qed"),
                    );
                    rest
                }
                FIELD_DATA => {
                    let (rest, len) = crate::util::nom_scale_compact_usize(rest)?;
                    let (rest, d) = nom::bytes::streaming::take(len)(rest)?;
                    data = Some(d.to_vec());
                    rest
                }
                _ => {
                    return Err(nom::Err::Failure(nom::error::make_error(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            };

            input = rest;
        }

        let expiry = expiry.ok_or_else(|| {
            nom::Err::Failure(nom::error::make_error(input, nom::error::ErrorKind::Verify))
        })?;

        let statement = Statement {
            proof,
            decryption_key,
            expiry,
            channel,
            topics,
            data,
        };

        Ok((input, statement))
    }
}

fn proof_parser(input: &[u8]) -> nom::IResult<&[u8], Proof> {
    let (input, variant) = nom::number::streaming::u8(input)?;
    match variant {
        PROOF_SR25519 => {
            let (input, signature) = nom::bytes::streaming::take(64u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(32u32)(input)?;
            Ok((
                input,
                Proof::Sr25519 {
                    signature: <[u8; 64]>::try_from(signature)
                        .expect("take(64) guarantees 64 bytes; qed"),
                    signer: <[u8; 32]>::try_from(signer)
                        .expect("take(32) guarantees 32 bytes; qed"),
                },
            ))
        }
        PROOF_ED25519 => {
            let (input, signature) = nom::bytes::streaming::take(64u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(32u32)(input)?;
            Ok((
                input,
                Proof::Ed25519 {
                    signature: <[u8; 64]>::try_from(signature)
                        .expect("take(64) guarantees 64 bytes; qed"),
                    signer: <[u8; 32]>::try_from(signer)
                        .expect("take(32) guarantees 32 bytes; qed"),
                },
            ))
        }
        PROOF_SECP256K1_ECDSA => {
            let (input, signature) = nom::bytes::streaming::take(65u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(33u32)(input)?;
            Ok((
                input,
                Proof::Secp256k1Ecdsa {
                    signature: <[u8; 65]>::try_from(signature)
                        .expect("take(65) guarantees 65 bytes; qed"),
                    signer: <[u8; 33]>::try_from(signer)
                        .expect("take(33) guarantees 33 bytes; qed"),
                },
            ))
        }
        PROOF_ON_CHAIN => {
            let (input, who) = nom::bytes::streaming::take(32u32)(input)?;
            let (input, block_hash) = nom::bytes::streaming::take(32u32)(input)?;
            let (input, event_index) = nom::number::streaming::le_u64(input)?;
            Ok((
                input,
                Proof::OnChain {
                    who: <[u8; 32]>::try_from(who).expect("take(32) guarantees 32 bytes; qed"),
                    block_hash: <[u8; 32]>::try_from(block_hash)
                        .expect("take(32) guarantees 32 bytes; qed"),
                    event_index,
                },
            ))
        }
        _ => Err(nom::Err::Failure(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_notification_multiple_statements() {
        let statement1 = Statement {
            proof: None,
            decryption_key: None,
            expiry: 100,
            channel: None,
            topics: Vec::new(),
            data: Some(b"first".to_vec()),
        };

        let statement2 = Statement {
            proof: None,
            decryption_key: None,
            expiry: 200,
            channel: None,
            topics: Vec::new(),
            data: Some(b"second".to_vec()),
        };

        let mut encoded = Vec::new();
        encoded.extend_from_slice(crate::util::encode_scale_compact_usize(2).as_ref());
        encoded.extend_from_slice(&encode_statement(&statement1).unwrap());
        encoded.extend_from_slice(&encode_statement(&statement2).unwrap());

        let decoded = decode_statement_notification(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        assert_eq!(decoded[0].1.expiry, 100);
        assert_eq!(decoded[1].1.expiry, 200);
        assert_eq!(decoded[0].1.data.as_deref(), Some(b"first".as_slice()));
        assert_eq!(decoded[1].1.data.as_deref(), Some(b"second".as_slice()));
    }

    #[test]
    fn complex_statement_with_all_fields() {
        let signature = [0xABu8; 64];
        let signer = [0xCDu8; 32];
        let decryption_key = [0xEFu8; 32];
        let channel = [0x12u8; 32];
        let topics: Vec<[u8; 32]> = (0..MAX_TOPICS).map(|i| [i as u8; 32]).collect();
        let data = vec![0x99; 5_000];

        let statement = Statement {
            proof: Some(Proof::Sr25519 { signature, signer }),
            decryption_key: Some(decryption_key),
            expiry: u64::MAX,
            channel: Some(channel),
            topics,
            data: Some(data),
        };

        let encoded = encode_statement(&statement).unwrap();
        let (remaining, decoded) = statement_parser(&encoded).unwrap();

        assert!(remaining.is_empty());
        assert_eq!(decoded.expiry, u64::MAX);
        assert_eq!(decoded.topics.len(), MAX_TOPICS);
        assert_eq!(decoded.data.as_ref().unwrap().len(), 5_000);
        assert!(decoded.proof.is_some());
        assert!(decoded.decryption_key.is_some());
        assert!(decoded.channel.is_some());
    }

    #[test]
    fn reject_out_of_order_fields() {
        let mut encoded = vec![8u8]; // Compact(2)
        encoded.push(FIELD_EXPIRY);
        encoded.extend_from_slice(&42u64.to_le_bytes());
        encoded.push(FIELD_DECRYPTION_KEY);
        encoded.extend_from_slice(&[0u8; 32]);

        assert!(statement_parser(&encoded).is_err());
    }

    #[test]
    fn reject_excessive_statement_count() {
        let count = MAX_STATEMENTS_PER_NOTIFICATION + 1;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(crate::util::encode_scale_compact_usize(count).as_ref());

        assert!(decode_statement_notification(&encoded).is_err());
    }

    #[test]
    fn reject_excessive_topic_count_encoding() {
        let topics: Vec<[u8; 32]> = (0..=MAX_TOPICS).map(|i| [i as u8; 32]).collect();

        let statement = Statement {
            proof: None,
            decryption_key: None,
            expiry: 0,
            channel: None,
            topics,
            data: None,
        };

        let result = encode_statement(&statement);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncodeStatementError::TooManyTopics { got, max }
            if got == MAX_TOPICS + 1 && max == MAX_TOPICS
        ));
    }

    #[test]
    fn reject_statement_without_expiry() {
        let mut encoded = vec![4u8];
        encoded.push(4);
        encoded.extend_from_slice(&[1u8; 32]);

        assert!(statement_parser(&encoded).is_err());
    }

    #[test]
    fn reject_unknown_field_tag() {
        let mut encoded = vec![8u8];
        encoded.push(2);
        encoded.extend_from_slice(&42u64.to_le_bytes());
        encoded.push(9); // Unknown tag
        encoded.extend_from_slice(&[0u8; 32]);

        assert!(statement_parser(&encoded).is_err());
    }

    #[test]
    fn topic_filter_any_matches_everything() {
        let filter = TopicFilter::Any;
        assert!(filter.matches(&[]));
        let topic = [1u8; 32];
        assert!(filter.matches(&[topic]));
    }

    #[test]
    fn topic_filter_match_any_empty_returns_false() {
        let filter = TopicFilter::match_any(Vec::new()).unwrap();
        let topic = [1u8; 32];
        assert!(!filter.matches(&[topic]));
        assert!(!filter.matches(&[]));
    }

    #[test]
    fn topic_filter_match_any_with_overlap() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let t3 = [3u8; 32];
        let filter = TopicFilter::match_any(vec![t1, t2]).unwrap();
        assert!(filter.matches(&[t1]));
        assert!(filter.matches(&[t2]));
        assert!(filter.matches(&[t3, t1]));
        assert!(!filter.matches(&[t3]));
        assert!(!filter.matches(&[]));
    }

    #[test]
    fn topic_filter_match_all() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let t3 = [3u8; 32];
        let filter = TopicFilter::match_all(vec![t1, t2]).unwrap();
        assert!(filter.matches(&[t1, t2]));
        assert!(filter.matches(&[t1, t2, t3]));
        assert!(!filter.matches(&[t1]));
        assert!(!filter.matches(&[t2]));
        assert!(!filter.matches(&[t3]));
        assert!(!filter.matches(&[]));
    }

    #[test]
    fn decode_encoded_statement() {
        // See "statement_encoding_matches_vec" in polkadot-sdk for the original statement fields
        let bytes = hex::decode(
            "1c00032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a181818\
             1818181818181818181818181818181818181818181818181818181818420000000000000001\
             dededededededededededededededededededededededededededededededede02e703000000\
             00000003cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0401\
             0101010101010101010101010101010101010101010101010101010101010105020202020202\
             020202020202020202020202020202020202020202020202020208083763",
        )
        .unwrap();

        let (remaining, decoded) = statement_parser(&bytes).unwrap();
        assert!(remaining.is_empty());

        assert!(matches!(
            decoded.proof,
            Some(Proof::OnChain { who, block_hash, event_index })
            if who == [42u8; 32]
                && block_hash == [24u8; 32]
                && event_index == 66
        ));
        assert_eq!(decoded.decryption_key, Some([0xde; 32]));
        assert_eq!(decoded.topics.len(), 2);
        assert_eq!(decoded.topics[0], [0x01; 32]);
        assert_eq!(decoded.topics[1], [0x02; 32]);
        assert_eq!(decoded.data.as_deref(), Some([55, 99].as_slice()));
        assert_eq!(decoded.expiry, 999);
        assert_eq!(decoded.channel, Some([0xcc; 32]));

        assert_eq!(encode_statement(&decoded).unwrap(), bytes);
    }
}
