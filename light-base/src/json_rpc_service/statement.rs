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

use crate::network_service::{self, BroadcastStatementResult};
use alloc::{format, string::String, vec::Vec};
use core::{num::NonZero, time::Duration};
use smoldot::json_rpc::methods::{HexString, InvalidReason, StatementSubmitResult, TopicFilter};
use smoldot::json_rpc::parse;
use smoldot::network::codec;

/// Configuration for the Statement Store protocol.
#[derive(Debug, Clone)]
pub struct StatementProtocolConfig {
    /// Per-subscription LRU cache size used for deduplicating delivered statements.
    max_seen_statements: NonZero<usize>,
    false_positive_rate: f64,
    bloom_seed: u128,
    affinity_update_interval: Duration,
}

impl StatementProtocolConfig {
    pub fn new(
        max_seen_statements: NonZero<usize>,
        false_positive_rate: f64,
        bloom_seed: u128,
        affinity_update_interval: Duration,
    ) -> Self {
        assert!(
            false_positive_rate.is_finite()
                && false_positive_rate > 0.0
                && false_positive_rate < 1.0
        );
        assert!(!affinity_update_interval.is_zero());
        StatementProtocolConfig {
            max_seen_statements,
            false_positive_rate,
            bloom_seed,
            affinity_update_interval,
        }
    }

    pub fn max_seen_statements(&self) -> NonZero<usize> {
        self.max_seen_statements
    }

    pub fn false_positive_rate(&self) -> f64 {
        self.false_positive_rate
    }

    pub fn bloom_seed(&self) -> u128 {
        self.bloom_seed
    }

    pub fn affinity_update_interval(&self) -> Duration {
        self.affinity_update_interval
    }
}

/// JSON-RPC error code answering a submission the statement store couldn't process.
///
/// Matches polkadot-sdk.
pub const STATEMENT_STORE_ERROR_CODE: i64 = 7001;

/// Submission failure reported as a JSON-RPC error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementSubmitError {
    /// The submitted bytes don't decode into a statement.
    InvalidEncoding,
    /// The statement is valid but reached none of the gossip-connected peers. A light
    /// client keeps no store, so a statement nobody received is permanently lost.
    NotSent { connected: usize },
}

impl StatementSubmitError {
    /// Builds the JSON-RPC error response answering this failure.
    ///
    /// # Panic
    ///
    /// Panics if `request_id_json` isn't valid JSON.
    pub fn to_json_rpc_error(&self, request_id_json: &str) -> String {
        // Both messages carry polkadot-sdk's prefix. It answers every statement-store failure with
        // the same code, so the message is all that tells these two apart.
        let message = match self {
            StatementSubmitError::InvalidEncoding => {
                String::from("Statement store error: Error decoding statement")
            }
            StatementSubmitError::NotSent { connected: 0 } => String::from(
                "Statement store error: No connected peers to broadcast the statement to",
            ),
            // Connected peers can still decline to queue, so the count separates the two.
            StatementSubmitError::NotSent { connected } => format!(
                "Statement store error: none of the {connected} connected peers accepted the \
                 statement"
            ),
        };

        parse::build_error_response(
            request_id_json,
            parse::ErrorResponse::ApplicationDefined(STATEMENT_STORE_ERROR_CODE, &message),
            None,
        )
    }
}

/// Validates a SCALE-encoded statement and broadcasts it to the network.
///
/// The checks run in the order polkadot-sdk's `Store::submit` applies them — expiry, then size,
/// then proof — so that a client submitting a statement failing several of them is told the same
/// reason a full node would give. Checks needing a local store or chain state are skipped.
///
/// The `broadcast` closure is only called if the statement is valid.
pub async fn validate_and_broadcast_statement<F, Fut>(
    encoded: &[u8],
    now_from_unix_epoch: Duration,
    broadcast: F,
) -> Result<StatementSubmitResult, StatementSubmitError>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = BroadcastStatementResult>,
{
    let Ok(statement) = codec::decode_statement(encoded) else {
        return Err(StatementSubmitError::InvalidEncoding);
    };

    if now_from_unix_epoch.as_secs() >= statement.expiry >> 32 {
        return Ok(StatementSubmitResult::Invalid(
            InvalidReason::AlreadyExpired,
        ));
    }

    if encoded.len() > codec::MAX_STATEMENT_SIZE {
        return Ok(StatementSubmitResult::Invalid(
            InvalidReason::EncodingTooLarge {
                submitted_size: encoded.len(),
                max_size: codec::MAX_STATEMENT_SIZE,
            },
        ));
    }

    if statement.proof.is_none() {
        return Ok(StatementSubmitResult::Invalid(InvalidReason::NoProof));
    }

    let broadcasted = broadcast(encoded.to_vec()).await;
    if broadcasted.sent == 0 {
        return Err(StatementSubmitError::NotSent {
            connected: broadcasted.total,
        });
    }

    Ok(StatementSubmitResult::New)
}

pub(super) struct StatementSubscription {
    topic_filter: TopicFilter,
    seen: Option<lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>>,
}

impl StatementSubscription {
    pub(super) fn new(topic_filter: TopicFilter, max_seen: Option<NonZero<usize>>) -> Self {
        Self {
            topic_filter,
            seen: max_seen
                .map(|cap| lru::LruCache::with_hasher(cap, fnv::FnvBuildHasher::default())),
        }
    }

    pub(super) fn accept(&mut self, hash: &[u8; 32], statement: &codec::Statement) -> bool {
        if !self.topic_filter.matches(&statement.topics) {
            return false;
        }
        if let Some(seen) = &mut self.seen {
            if seen.put(*hash, ()).is_some() {
                return false;
            }
        }
        true
    }
}

/// Set of active statement subscriptions together with a reverse index mapping each topic to the
/// subscriptions that reference it.
///
/// The reverse index lets statement matching scale with the number of subscriptions that share a
/// topic with the incoming statement, rather than with the total number of subscriptions.
pub(super) struct StatementSubscriptions {
    /// Maps subscription ID to its state.
    subscriptions: hashbrown::HashMap<String, StatementSubscription, fnv::FnvBuildHasher>,

    /// Reverse index: maps a topic to the IDs of all subscriptions whose filter references it.
    /// Only populated for `MatchAny`/`MatchAll` filters with a non-empty topic list.
    by_topic: hashbrown::HashMap<
        [u8; 32],
        hashbrown::HashSet<String, fnv::FnvBuildHasher>,
        fnv::FnvBuildHasher,
    >,

    /// IDs of subscriptions that match every statement irrespective of its topics: either
    /// `TopicFilter::Any`, or a `TopicFilter::MatchAll` whose topic list is empty.
    wildcard: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
}

impl StatementSubscriptions {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                capacity,
                Default::default(),
            ),
            by_topic: hashbrown::HashMap::with_hasher(Default::default()),
            wildcard: hashbrown::HashSet::with_hasher(Default::default()),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    /// Inserts a new subscription and updates the reverse index.
    pub(super) fn insert(
        &mut self,
        id: String,
        topic_filter: TopicFilter,
        max_seen: Option<NonZero<usize>>,
    ) {
        match &topic_filter {
            TopicFilter::Any => {
                self.wildcard.insert(id.clone());
            }
            // An empty `MatchAll` filter matches every statement.
            TopicFilter::MatchAll(topics) if topics.is_empty() => {
                self.wildcard.insert(id.clone());
            }
            TopicFilter::MatchAll(topics) | TopicFilter::MatchAny(topics) => {
                for topic in topics {
                    self.by_topic
                        .entry(*topic)
                        .or_insert_with(|| hashbrown::HashSet::with_hasher(Default::default()))
                        .insert(id.clone());
                }
            }
        }

        self.subscriptions
            .insert(id, StatementSubscription::new(topic_filter, max_seen));
    }

    /// Removes a subscription and cleans up the reverse index. Returns whether it existed.
    pub(super) fn remove(&mut self, id: &str) -> bool {
        let Some(sub) = self.subscriptions.remove(id) else {
            return false;
        };

        match &sub.topic_filter {
            TopicFilter::Any => {
                self.wildcard.remove(id);
            }
            TopicFilter::MatchAll(topics) if topics.is_empty() => {
                self.wildcard.remove(id);
            }
            TopicFilter::MatchAll(topics) | TopicFilter::MatchAny(topics) => {
                for topic in topics {
                    if let Some(ids) = self.by_topic.get_mut(topic) {
                        ids.remove(id);
                        if ids.is_empty() {
                            self.by_topic.remove(topic);
                        }
                    }
                }
            }
        }

        true
    }

    pub(super) fn shrink_to_fit(&mut self) {
        self.subscriptions.shrink_to_fit();
        for ids in self.by_topic.values_mut() {
            ids.shrink_to_fit();
        }
        self.by_topic.shrink_to_fit();
        self.wildcard.shrink_to_fit();
    }

    /// Matches a batch of statements against the subscriptions.
    ///
    /// Returns, for every subscription that accepts at least one statement, the list of re-encoded
    /// matching statements. Uses the reverse index to only consider subscriptions that either match
    /// everything or share a topic with the statement; the precise per-subscription filter and
    /// deduplication is then applied via [`StatementSubscription::accept`].
    pub(super) fn matching(
        &mut self,
        statements: &[([u8; 32], codec::Statement)],
    ) -> Vec<(String, Vec<HexString>)> {
        // Disjoint borrows: `subscriptions` is mutated while `by_topic`/`wildcard` are only read.
        let Self {
            subscriptions,
            by_topic,
            wildcard,
        } = self;

        // Subscription ID -> its matching re-encoded statements.
        let mut out: hashbrown::HashMap<&str, Vec<HexString>, fnv::FnvBuildHasher> =
            hashbrown::HashMap::with_hasher(Default::default());
        // Reused across statements to avoid reallocating.
        let mut candidates: hashbrown::HashSet<&str, fnv::FnvBuildHasher> =
            hashbrown::HashSet::with_hasher(Default::default());

        for (hash, statement) in statements {
            candidates.clear();
            candidates.extend(wildcard.iter().map(String::as_str));
            for topic in &statement.topics {
                if let Some(ids) = by_topic.get(topic) {
                    candidates.extend(ids.iter().map(String::as_str));
                }
            }

            // Re-encoded lazily on first match and reused for every matching subscription.
            let mut encoded: Option<HexString> = None;
            for id in &candidates {
                let sub = subscriptions
                    .get_mut(*id)
                    .expect("`candidates` is a subset of `subscriptions`; qed");
                if sub.accept(hash, statement) {
                    let encoded = encoded.get_or_insert_with(|| {
                        HexString(
                            codec::encode_statement(statement)
                                .expect("re-encoding a decoded statement always succeeds; qed"),
                        )
                    });
                    out.entry(*id).or_default().push(encoded.clone());
                }
            }
        }

        out.into_iter()
            .map(|(id, matching)| (String::from(id), matching))
            .collect()
    }

    pub(super) fn build_combined_affinity_filter(
        &self,
        config: &StatementProtocolConfig,
    ) -> network_service::AffinityFilter {
        let mut all_topics: Vec<&[u8; 32]> = Vec::new();

        for sub in self.subscriptions.values() {
            match &sub.topic_filter {
                TopicFilter::Any => {
                    return network_service::AffinityFilter::match_all(config.bloom_seed());
                }
                TopicFilter::MatchAll(topics) | TopicFilter::MatchAny(topics) => {
                    all_topics.extend(topics.iter());
                }
            }
        }

        network_service::AffinityFilter::from_topics(
            all_topics.into_iter(),
            config.bloom_seed(),
            config.false_positive_rate(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;
    use core::time::Duration;
    use futures_lite::future::block_on;

    const SEED: u128 = 0x5EED_5EED_5EED_5EED_5EED_5EED_5EED_5EED;
    const FPR: f64 = 0.01;

    fn test_config() -> StatementProtocolConfig {
        StatementProtocolConfig::new(
            NonZero::new(128).unwrap(),
            FPR,
            SEED,
            Duration::from_secs(1),
        )
    }

    fn make_subscriptions(
        entries: Vec<(&str, TopicFilter, Option<NonZero<usize>>)>,
    ) -> StatementSubscriptions {
        let mut subs = StatementSubscriptions::with_capacity(entries.len());
        for (id, filter, max_seen) in entries {
            subs.insert(id.to_string(), filter, max_seen);
        }
        subs
    }

    fn statement_with_topics(topics: Vec<[u8; 32]>) -> codec::Statement {
        codec::Statement {
            proof: None,
            decryption_key: None,
            expiry: 42,
            channel: None,
            topics,
            data: None,
        }
    }

    const NOW: Duration = Duration::from_secs(1_000);

    /// Expiration timestamp, in the most significant 32 bits, later than [`NOW`].
    const FUTURE_EXPIRY: u64 = 2_000 << 32;

    fn encoded_statement(with_proof: bool, expiry: u64, data: Option<Vec<u8>>) -> Vec<u8> {
        codec::encode_statement(&codec::Statement {
            proof: with_proof.then(|| codec::Proof::Ed25519 {
                signature: [0; 64],
                signer: [0; 32],
            }),
            decryption_key: None,
            expiry,
            channel: None,
            topics: Vec::new(),
            data,
        })
        .unwrap()
    }

    #[test]
    fn validate_and_broadcast_invalid_encoding() {
        let result = block_on(validate_and_broadcast_statement(
            &[0xff, 0xff],
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(result, Err(StatementSubmitError::InvalidEncoding));
    }

    #[test]
    fn validate_and_broadcast_already_expired() {
        // The statement also has no proof: the expiry check runs first.
        let encoded = encoded_statement(false, 500 << 32, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            Ok(StatementSubmitResult::Invalid(
                InvalidReason::AlreadyExpired
            ))
        );
    }

    #[test]
    fn validate_and_broadcast_expiry_equal_to_now_is_expired() {
        let encoded = encoded_statement(true, NOW.as_secs() << 32, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            Ok(StatementSubmitResult::Invalid(
                InvalidReason::AlreadyExpired
            ))
        );
    }

    #[test]
    fn validate_and_broadcast_encoding_too_large() {
        // The statement also has no proof: the size check runs before the proof check.
        let encoded = encoded_statement(false, FUTURE_EXPIRY, Some(vec![0; 1024 * 1024]));
        assert!(encoded.len() > codec::MAX_STATEMENT_SIZE);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            Ok(StatementSubmitResult::Invalid(
                InvalidReason::EncodingTooLarge {
                    submitted_size: encoded.len(),
                    max_size: codec::MAX_STATEMENT_SIZE,
                }
            ))
        );
    }

    #[test]
    fn validate_and_broadcast_no_proof() {
        let encoded = encoded_statement(false, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            Ok(StatementSubmitResult::Invalid(InvalidReason::NoProof))
        );
    }

    #[test]
    fn validate_and_broadcast_no_peers() {
        let encoded = encoded_statement(true, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            BroadcastStatementResult { sent: 0, total: 0 }
        }));
        assert_eq!(result, Err(StatementSubmitError::NotSent { connected: 0 }));
    }

    #[test]
    fn submit_errors_carry_the_statement_store_code() {
        // Both failures answer with polkadot-sdk's single statement-store code, telling themselves
        // apart by message alone, exactly as it does.
        assert_eq!(
            StatementSubmitError::InvalidEncoding.to_json_rpc_error("7"),
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":7001,"message":"Statement store error: Error decoding statement"}}"#
        );
        assert_eq!(
            StatementSubmitError::NotSent { connected: 0 }.to_json_rpc_error("7"),
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":7001,"message":"Statement store error: No connected peers to broadcast the statement to"}}"#
        );
        // Connected peers that took nothing must not read as no peers.
        assert_eq!(
            StatementSubmitError::NotSent { connected: 5 }.to_json_rpc_error("7"),
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":7001,"message":"Statement store error: none of the 5 connected peers accepted the statement"}}"#
        );
    }

    #[test]
    fn validate_and_broadcast_reaching_no_peer_is_not_new() {
        // Gossip-connected peers whose statement substream is missing or whose queue is full leave
        // the statement unsent. Answering `new` would tell the client it was published.
        let encoded = encoded_statement(true, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            BroadcastStatementResult { sent: 0, total: 5 }
        }));
        assert_eq!(result, Err(StatementSubmitError::NotSent { connected: 5 }));
    }

    #[test]
    fn validate_and_broadcast_new() {
        let encoded = encoded_statement(true, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement(&encoded, NOW, |_| async {
            BroadcastStatementResult { sent: 3, total: 5 }
        }));
        assert_eq!(result, Ok(StatementSubmitResult::New));
    }

    #[test]
    fn build_combined_affinity_empty_subscriptions() {
        let config = test_config();
        let subs = make_subscriptions(vec![]);
        let filter = subs.build_combined_affinity_filter(&config);

        // Empty subscription set: no topics are ever in the filter.
        assert!(!filter.contains(&[1u8; 32]));
        // A statement with no topics (broadcast) still matches.
        let broadcast: &[&[u8; 32]] = &[];
        assert!(filter.matches_statement(broadcast));
    }

    #[test]
    fn build_combined_affinity_any_filter_matches_everything() {
        let config = test_config();
        let subs = make_subscriptions(vec![("s", TopicFilter::Any, None)]);
        let filter = subs.build_combined_affinity_filter(&config);

        // TopicFilter::Any returns the broadcast `match_all` filter: every topic matches.
        assert!(filter.contains(&[1u8; 32]));
        assert!(filter.contains(&[99u8; 32]));
        let t = [7u8; 32];
        assert!(filter.matches_statement(&[&t]));
    }

    #[test]
    fn build_combined_affinity_match_any_union() {
        let config = test_config();
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let subs = make_subscriptions(vec![
            ("a", TopicFilter::match_any(vec![t1]).unwrap(), None),
            ("b", TopicFilter::match_any(vec![t2]).unwrap(), None),
        ]);
        let filter = subs.build_combined_affinity_filter(&config);

        assert!(filter.contains(&t1));
        assert!(filter.contains(&t2));
    }

    #[test]
    fn accept_fresh_statement_passes() {
        let t1 = [1u8; 32];
        let mut sub =
            StatementSubscription::new(TopicFilter::match_any(vec![t1]).unwrap(), NonZero::new(8));
        let stmt = statement_with_topics(vec![t1]);
        assert!(sub.accept(&[0xbb; 32], &stmt));
    }

    #[test]
    fn accept_duplicate_returns_false() {
        let mut sub = StatementSubscription::new(TopicFilter::Any, NonZero::new(8));
        let stmt = statement_with_topics(vec![]);
        let hash = [0xcc; 32];
        assert!(sub.accept(&hash, &stmt));
        assert!(!sub.accept(&hash, &stmt));
    }

    #[test]
    fn accept_lru_eviction_allows_resubmit() {
        let mut sub = StatementSubscription::new(TopicFilter::Any, NonZero::new(2));
        let stmt = statement_with_topics(vec![]);
        let h_a = [0xa; 32];
        let h_b = [0xb; 32];
        let h_c = [0xc; 32];

        assert!(sub.accept(&h_a, &stmt));
        assert!(sub.accept(&h_b, &stmt));
        // Inserting a third eviction-capacity 2 item evicts h_a (oldest).
        assert!(sub.accept(&h_c, &stmt));
        // h_a was evicted: it is accepted again as if fresh.
        assert!(sub.accept(&h_a, &stmt));
    }

    #[test]
    fn dedup_is_per_subscription() {
        let mut sub_a = StatementSubscription::new(TopicFilter::Any, NonZero::new(8));
        let mut sub_b = StatementSubscription::new(TopicFilter::Any, NonZero::new(8));
        let stmt = statement_with_topics(vec![]);
        let hash = [0xee; 32];

        assert!(sub_a.accept(&hash, &stmt));
        assert!(!sub_a.accept(&hash, &stmt));
        // Same hash on a different subscription is still fresh: caches are independent.
        assert!(sub_b.accept(&hash, &stmt));
    }

    /// Builds a `(hash, statement)` batch entry from a list of topics.
    fn batch_entry(hash: u8, topics: Vec<[u8; 32]>) -> ([u8; 32], codec::Statement) {
        ([hash; 32], statement_with_topics(topics))
    }

    /// Collects the IDs of all subscriptions that matched at least once.
    fn matched_ids(matches: &[(String, Vec<HexString>)]) -> Vec<String> {
        let mut ids: Vec<String> = matches.iter().map(|(id, _)| id.clone()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn matching_match_any_only_returns_relevant_subscriptions() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs = make_subscriptions(vec![
            ("a", TopicFilter::match_any(vec![t1]).unwrap(), None),
            ("b", TopicFilter::match_any(vec![t2]).unwrap(), None),
        ]);

        // A statement carrying only `t1` must match `a` and not `b`.
        let matches = subs.matching(&[batch_entry(0xaa, vec![t1])]);
        assert_eq!(matched_ids(&matches), vec!["a".to_string()]);

        // A statement with an unrelated topic matches nothing.
        let matches = subs.matching(&[batch_entry(0xbb, vec![[9u8; 32]])]);
        assert!(matches.is_empty());
    }

    #[test]
    fn matching_wildcard_filters_match_every_statement() {
        // `Any` and an empty `MatchAll` both match every statement, with or without topics.
        let mut subs = make_subscriptions(vec![
            ("any", TopicFilter::Any, None),
            ("all", TopicFilter::match_all(vec![]).unwrap(), None),
        ]);

        let matches = subs.matching(&[batch_entry(0x01, vec![[7u8; 32]])]);
        assert_eq!(
            matched_ids(&matches),
            vec!["all".to_string(), "any".to_string()]
        );

        let matches = subs.matching(&[batch_entry(0x02, vec![])]);
        assert_eq!(
            matched_ids(&matches),
            vec!["all".to_string(), "any".to_string()]
        );
    }

    #[test]
    fn matching_match_all_requires_every_topic() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs = make_subscriptions(vec![(
            "all",
            TopicFilter::match_all(vec![t1, t2]).unwrap(),
            None,
        )]);

        // A statement carrying only one of the required topics is a candidate via the reverse
        // index but must be rejected by the precise re-check.
        let matches = subs.matching(&[batch_entry(0xaa, vec![t1])]);
        assert!(matches.is_empty());

        // A statement carrying both topics matches.
        let matches = subs.matching(&[batch_entry(0xbb, vec![t1, t2])]);
        assert_eq!(matched_ids(&matches), vec!["all".to_string()]);
    }

    #[test]
    fn matching_empty_match_any_never_matches() {
        let mut subs = make_subscriptions(vec![(
            "none",
            TopicFilter::match_any(vec![]).unwrap(),
            None,
        )]);

        let matches = subs.matching(&[batch_entry(0x01, vec![[1u8; 32]])]);
        assert!(matches.is_empty());
        let matches = subs.matching(&[batch_entry(0x02, vec![])]);
        assert!(matches.is_empty());
    }

    #[test]
    fn matching_dedup_applies_across_batches() {
        let t1 = [1u8; 32];
        let mut subs = make_subscriptions(vec![(
            "a",
            TopicFilter::match_any(vec![t1]).unwrap(),
            NonZero::new(8),
        )]);

        let entry = batch_entry(0xaa, vec![t1]);
        let matches = subs.matching(&[entry.clone()]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.len(), 1);

        // The same statement hash is deduplicated and produces no further notification.
        let matches = subs.matching(&[entry]);
        assert!(matches.is_empty());
    }

    #[test]
    fn matching_groups_multiple_statements_per_subscription() {
        let t1 = [1u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);

        let matches = subs.matching(&[batch_entry(0x01, vec![t1]), batch_entry(0x02, vec![t1])]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "a");
        assert_eq!(matches[0].1.len(), 2);
    }

    #[test]
    fn remove_cleans_reverse_index() {
        let t1 = [1u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);

        assert!(subs.remove("a"));
        assert!(!subs.remove("a"));
        assert!(subs.is_empty());
        // The topic entry must have been cleaned up, so a matching statement finds nothing.
        let matches = subs.matching(&[batch_entry(0xaa, vec![t1])]);
        assert!(matches.is_empty());
    }
}
