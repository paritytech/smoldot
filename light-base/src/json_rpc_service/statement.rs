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
use alloc::{string::String, vec::Vec};
use core::{num::NonZero, time::Duration};
use smoldot::json_rpc::methods::{
    HexString, InternalError, InvalidReason, StatementSubmitInvalidReason, StatementSubmitOutcome,
    StatementSubmitResult, TopicFilter,
};
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

/// Validates a SCALE-encoded statement and broadcasts it to the network.
///
/// Returns the appropriate [`StatementSubmitResult`] based on the decode and broadcast outcome.
/// The `broadcast` closure is only called if the statement is valid.
pub async fn validate_and_broadcast_statement<F, Fut>(
    encoded: &[u8],
    broadcast: F,
) -> StatementSubmitResult
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = BroadcastStatementResult>,
{
    if codec::decode_statement(encoded).is_err() {
        return StatementSubmitResult::Invalid {
            reason: InvalidReason::Encoding,
        };
    }

    let broadcasted = broadcast(encoded.to_vec()).await;
    if broadcasted.total == 0 {
        StatementSubmitResult::InternalError {
            error: InternalError::NoConnectedPeers,
        }
    } else {
        StatementSubmitResult::New
    }
}

/// Failure of a `statement_unstable_submit` request, reported as a JSON-RPC error rather than a
/// [`StatementSubmitOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementSubmitError {
    /// The submitted bytes don't decode into a statement.
    InvalidEncoding,
    /// The statement is valid but there were no connected peers to broadcast it to.
    NoConnectedPeers,
}

/// Validates a SCALE-encoded statement and broadcasts it, following the
/// `statement_unstable_submit` semantics.
pub async fn validate_and_broadcast_statement_unstable<F, Fut>(
    encoded: &[u8],
    now_from_unix_epoch: Duration,
    broadcast: F,
) -> Result<StatementSubmitOutcome, StatementSubmitError>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = BroadcastStatementResult>,
{
    let Ok(statement) = codec::decode_statement(encoded) else {
        return Err(StatementSubmitError::InvalidEncoding);
    };

    // The most significant 32 bits of `expiry` are the expiration timestamp in seconds since
    // the UNIX epoch.
    if now_from_unix_epoch.as_secs() >= statement.expiry >> 32 {
        return Ok(StatementSubmitOutcome::Invalid(
            StatementSubmitInvalidReason::AlreadyExpired,
        ));
    }

    if encoded.len() > codec::MAX_STATEMENT_SIZE {
        return Ok(StatementSubmitOutcome::Invalid(
            StatementSubmitInvalidReason::EncodingTooLarge {
                submitted_size: encoded.len(),
                max_size: codec::MAX_STATEMENT_SIZE,
            },
        ));
    }

    if statement.proof.is_none() {
        return Ok(StatementSubmitOutcome::Invalid(
            StatementSubmitInvalidReason::NoProof,
        ));
    }

    let broadcasted = broadcast(encoded.to_vec()).await;
    if broadcasted.total == 0 {
        return Err(StatementSubmitError::NoConnectedPeers);
    }

    Ok(StatementSubmitOutcome::New)
}

/// Identifies a filter within the subscription it is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct FilterId(u64);

/// One statement subscription: a set of topic filters sharing one deduplication cache.
pub(super) struct StatementSubscription {
    filters: hashbrown::HashMap<FilterId, TopicFilter, fnv::FnvBuildHasher>,

    /// Id given to the next filter attached to this subscription. Ids are never reused, so that a
    /// removed filter can't be confused with a later one.
    next_filter_id: u64,

    seen: Option<lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>>,
}

impl StatementSubscription {
    fn new(max_seen: Option<NonZero<usize>>) -> Self {
        Self {
            filters: hashbrown::HashMap::with_hasher(Default::default()),
            next_filter_id: 0,
            seen: max_seen
                .map(|cap| lru::LruCache::with_hasher(cap, fnv::FnvBuildHasher::default())),
        }
    }

    /// Attaches `topic_filter` to this subscription and returns the id identifying it.
    fn add_filter(&mut self, topic_filter: TopicFilter) -> FilterId {
        let filter_id = FilterId(self.next_filter_id);
        self.next_filter_id += 1;
        self.filters.insert(filter_id, topic_filter);
        filter_id
    }

    /// Returns whether at least one filter of this subscription matches `topics`.
    fn matches(&self, topics: &[codec::Topic]) -> bool {
        self.filters
            .values()
            .any(|topic_filter| topic_filter.matches(topics))
    }

    /// Returns the topics that at least one filter of this subscription references, and whether one
    /// of them matches every statement irrespective of its topics.
    fn indexed_topics(&self) -> (Vec<codec::Topic>, bool) {
        let mut topics = Vec::new();
        let mut wildcard = false;

        for topic_filter in self.filters.values() {
            match indexed_topics(topic_filter) {
                None => wildcard = true,
                Some(filter_topics) => topics.extend(filter_topics),
            }
        }

        (topics, wildcard)
    }

    /// Records the statement of the given hash as delivered to this subscription. Returns `false`
    /// if it was already delivered.
    fn accept(&mut self, hash: &[u8; 32]) -> bool {
        match &mut self.seen {
            Some(seen) => seen.put(*hash, ()).is_none(),
            None => true,
        }
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

    /// IDs of subscriptions having a filter that matches every statement irrespective of its
    /// topics: either `TopicFilter::Any`, or a `TopicFilter::MatchAll` whose topic list is empty.
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

    /// Inserts a new subscription holding `topic_filter` as its only filter.
    pub(super) fn insert(
        &mut self,
        id: String,
        topic_filter: TopicFilter,
        max_seen: Option<NonZero<usize>>,
    ) {
        self.subscriptions
            .insert(id.clone(), StatementSubscription::new(max_seen));
        self.add_filter(&id, topic_filter)
            .expect("subscription was just inserted; qed");
    }

    /// Attaches a filter to an existing subscription and updates the reverse index. Returns the id
    /// identifying the filter within that subscription, or `None` if the subscription is unknown.
    pub(super) fn add_filter(
        &mut self,
        sub_id: &str,
        topic_filter: TopicFilter,
    ) -> Option<FilterId> {
        // Determined before handing the filter over to the subscription, which then owns it.
        let indexed_topics = indexed_topics(&topic_filter);

        let filter_id = self.subscriptions.get_mut(sub_id)?.add_filter(topic_filter);

        match indexed_topics {
            None => {
                self.wildcard.insert(String::from(sub_id));
            }
            Some(topics) => {
                for topic in topics {
                    self.by_topic
                        .entry(topic)
                        .or_insert_with(|| hashbrown::HashSet::with_hasher(Default::default()))
                        .insert(String::from(sub_id));
                }
            }
        }

        Some(filter_id)
    }

    /// Removes a subscription together with all its filters, and cleans up the reverse index.
    /// Returns whether it existed.
    pub(super) fn remove(&mut self, id: &str) -> bool {
        let Some(sub) = self.subscriptions.remove(id) else {
            return false;
        };

        let (topics, wildcard) = sub.indexed_topics();

        if wildcard {
            self.wildcard.remove(id);
        }

        for topic in topics {
            if let Some(ids) = self.by_topic.get_mut(&topic) {
                ids.remove(id);
                if ids.is_empty() {
                    self.by_topic.remove(&topic);
                }
            }
        }

        true
    }

    pub(super) fn shrink_to_fit(&mut self) {
        self.subscriptions.shrink_to_fit();
        for sub in self.subscriptions.values_mut() {
            sub.filters.shrink_to_fit();
        }
        for entries in self.by_topic.values_mut() {
            entries.shrink_to_fit();
        }
        self.by_topic.shrink_to_fit();
        self.wildcard.shrink_to_fit();
    }

    /// Matches a batch of statements against the subscriptions.
    ///
    /// Returns, for every subscription that accepts at least one statement, the list of re-encoded
    /// matching statements. Uses the reverse index to only consider subscriptions that either match
    /// everything or share a topic with the statement; the precise per-filter check and the
    /// deduplication are then applied to each candidate. A statement matched by several filters of
    /// the same subscription is reported once.
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
                if sub.matches(&statement.topics) && sub.accept(hash) {
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
            for topic_filter in sub.filters.values() {
                match topic_filter {
                    TopicFilter::Any => {
                        return network_service::AffinityFilter::match_all(config.bloom_seed());
                    }
                    TopicFilter::MatchAll(topics) | TopicFilter::MatchAny(topics) => {
                        all_topics.extend(topics.iter());
                    }
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

/// Returns the topics under which a filter is indexed, or `None` if it matches every statement
/// irrespective of its topics.
fn indexed_topics(topic_filter: &TopicFilter) -> Option<Vec<codec::Topic>> {
    match topic_filter {
        TopicFilter::Any => None,
        TopicFilter::MatchAll(topics) | TopicFilter::MatchAny(topics) => Some(topics.clone()),
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

    fn valid_statement() -> Vec<u8> {
        codec::encode_statement(&codec::Statement {
            proof: None,
            decryption_key: None,
            expiry: 42,
            channel: None,
            topics: Vec::new(),
            data: None,
        })
        .unwrap()
    }

    const NOW: Duration = Duration::from_secs(1_000);

    /// Expiration timestamp, in the most significant 32 bits, later than [`NOW`].
    const FUTURE_EXPIRY: u64 = 2_000 << 32;

    fn encoded_statement(with_proof: bool, expiry: u64, data: Option<Vec<u8>>) -> Vec<u8> {
        codec::encode_statement(&codec::Statement {
            proof: with_proof.then(|| codec::Proof::Sr25519 {
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
    fn unstable_submit_invalid_encoding() {
        let result = block_on(validate_and_broadcast_statement_unstable(
            &[0xff, 0xff],
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(result, Err(StatementSubmitError::InvalidEncoding));
    }

    #[test]
    fn unstable_submit_already_expired() {
        // The statement also has no proof: the expiry check runs first.
        let encoded = encoded_statement(false, 500 << 32, None);
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(
            result,
            Ok(StatementSubmitOutcome::Invalid(
                StatementSubmitInvalidReason::AlreadyExpired
            ))
        );
    }

    #[test]
    fn unstable_submit_expiry_equal_to_now_is_expired() {
        let encoded = encoded_statement(true, NOW.as_secs() << 32, None);
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(
            result,
            Ok(StatementSubmitOutcome::Invalid(
                StatementSubmitInvalidReason::AlreadyExpired
            ))
        );
    }

    #[test]
    fn unstable_submit_encoding_too_large() {
        // The statement also has no proof: the size check runs before the proof check.
        let encoded = encoded_statement(false, FUTURE_EXPIRY, Some(vec![0; 1024 * 1024]));
        assert!(encoded.len() > codec::MAX_STATEMENT_SIZE);
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(
            result,
            Ok(StatementSubmitOutcome::Invalid(
                StatementSubmitInvalidReason::EncodingTooLarge {
                    submitted_size: encoded.len(),
                    max_size: codec::MAX_STATEMENT_SIZE,
                }
            ))
        );
    }

    #[test]
    fn unstable_submit_no_proof() {
        let encoded = encoded_statement(false, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |_| async { unreachable!() },
        ));
        assert_eq!(
            result,
            Ok(StatementSubmitOutcome::Invalid(
                StatementSubmitInvalidReason::NoProof
            ))
        );
    }

    #[test]
    fn unstable_submit_no_peers() {
        let encoded = encoded_statement(true, FUTURE_EXPIRY, None);
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |_| async { BroadcastStatementResult { sent: 0, total: 0 } },
        ));
        assert_eq!(result, Err(StatementSubmitError::NoConnectedPeers));
    }

    #[test]
    fn unstable_submit_new() {
        let encoded = encoded_statement(true, FUTURE_EXPIRY, None);
        let expected_bytes = encoded.clone();
        let result = block_on(validate_and_broadcast_statement_unstable(
            &encoded,
            NOW,
            |bytes| async move {
                assert_eq!(bytes, expected_bytes);
                BroadcastStatementResult { sent: 3, total: 5 }
            },
        ));
        assert_eq!(result, Ok(StatementSubmitOutcome::New));
    }

    #[test]
    fn validate_and_broadcast_invalid_encoding() {
        let result = block_on(validate_and_broadcast_statement(&[0xff, 0xff], |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            StatementSubmitResult::Invalid {
                reason: InvalidReason::Encoding
            }
        );
    }

    #[test]
    fn validate_and_broadcast_no_peers() {
        let result = block_on(validate_and_broadcast_statement(
            &valid_statement(),
            |_| async { BroadcastStatementResult { sent: 0, total: 0 } },
        ));
        assert_eq!(
            result,
            StatementSubmitResult::InternalError {
                error: InternalError::NoConnectedPeers
            }
        );
    }

    #[test]
    fn validate_and_broadcast_new() {
        let result = block_on(validate_and_broadcast_statement(
            &valid_statement(),
            |_| async { BroadcastStatementResult { sent: 3, total: 5 } },
        ));
        assert_eq!(result, StatementSubmitResult::New);
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
        let mut sub = StatementSubscription::new(NonZero::new(8));
        assert!(sub.accept(&[0xbb; 32]));
    }

    #[test]
    fn accept_duplicate_returns_false() {
        let mut sub = StatementSubscription::new(NonZero::new(8));
        let hash = [0xcc; 32];
        assert!(sub.accept(&hash));
        assert!(!sub.accept(&hash));
    }

    #[test]
    fn accept_lru_eviction_allows_resubmit() {
        let mut sub = StatementSubscription::new(NonZero::new(2));
        let h_a = [0xa; 32];
        let h_b = [0xb; 32];
        let h_c = [0xc; 32];

        assert!(sub.accept(&h_a));
        assert!(sub.accept(&h_b));
        // Inserting a third eviction-capacity 2 item evicts h_a (oldest).
        assert!(sub.accept(&h_c));
        // h_a was evicted: it is accepted again as if fresh.
        assert!(sub.accept(&h_a));
    }

    #[test]
    fn dedup_is_per_subscription() {
        let mut sub_a = StatementSubscription::new(NonZero::new(8));
        let mut sub_b = StatementSubscription::new(NonZero::new(8));
        let hash = [0xee; 32];

        assert!(sub_a.accept(&hash));
        assert!(!sub_a.accept(&hash));
        // Same hash on a different subscription is still fresh: caches are independent.
        assert!(sub_b.accept(&hash));
    }

    #[test]
    fn matches_when_any_filter_does() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut sub = StatementSubscription::new(None);
        sub.add_filter(TopicFilter::match_any(vec![t1]).unwrap());
        sub.add_filter(TopicFilter::match_any(vec![t2]).unwrap());

        assert!(sub.matches(&[t1]));
        assert!(sub.matches(&[t2]));
        assert!(!sub.matches(&[[9u8; 32]]));
    }

    #[test]
    fn indexed_topics_gathers_every_filter() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut sub = StatementSubscription::new(None);
        sub.add_filter(TopicFilter::match_any(vec![t1]).unwrap());
        sub.add_filter(TopicFilter::match_all(vec![t2]).unwrap());

        let (mut topics, wildcard) = sub.indexed_topics();
        topics.sort_unstable();
        assert_eq!(topics, vec![t1, t2]);
        assert!(!wildcard);

        // A single wildcard filter is enough to flag the whole subscription.
        sub.add_filter(TopicFilter::Any);
        assert!(sub.indexed_topics().1);
    }

    #[test]
    fn filter_ids_are_never_reused() {
        let mut sub = StatementSubscription::new(None);
        let first = sub.add_filter(TopicFilter::Any);
        sub.filters.remove(&first);
        let second = sub.add_filter(TopicFilter::Any);
        assert_ne!(first, second);
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
        // `Any` matches every statement, with or without topics.
        let mut subs = make_subscriptions(vec![("any", TopicFilter::Any, None)]);

        let matches = subs.matching(&[batch_entry(0x01, vec![[7u8; 32]])]);
        assert_eq!(matched_ids(&matches), vec!["any".to_string()]);

        let matches = subs.matching(&[batch_entry(0x02, vec![])]);
        assert_eq!(matched_ids(&matches), vec!["any".to_string()]);
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

    #[test]
    fn add_filter_on_unknown_subscription_returns_none() {
        let mut subs = make_subscriptions(vec![]);
        assert!(subs.add_filter("nope", TopicFilter::Any).is_none());
    }

    #[test]
    fn matching_accepts_a_statement_matched_by_any_filter() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);
        subs.add_filter("a", TopicFilter::match_any(vec![t2]).unwrap())
            .unwrap();

        // Each filter pulls in the statements of its own topic.
        let matches = subs.matching(&[batch_entry(0x01, vec![t1]), batch_entry(0x02, vec![t2])]);
        assert_eq!(matched_ids(&matches), vec!["a".to_string()]);
        assert_eq!(matches[0].1.len(), 2);

        // A statement matching none of the filters is not accepted.
        let matches = subs.matching(&[batch_entry(0x03, vec![[9u8; 32]])]);
        assert!(matches.is_empty());
    }

    #[test]
    fn matching_reports_a_statement_once_per_subscription() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs = make_subscriptions(vec![(
            "a",
            TopicFilter::match_any(vec![t1]).unwrap(),
            NonZero::new(8),
        )]);
        subs.add_filter("a", TopicFilter::match_any(vec![t2]).unwrap())
            .unwrap();
        subs.add_filter("a", TopicFilter::Any).unwrap();

        // All three filters match, yet the statement is reported a single time.
        let matches = subs.matching(&[batch_entry(0xaa, vec![t1, t2])]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.len(), 1);
    }

    #[test]
    fn matching_dedups_a_filter_indexed_under_several_topics() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        // Without a deduplication cache, a filter indexed under both topics would otherwise report
        // the statement once per topic it shares with it.
        let mut subs = make_subscriptions(vec![(
            "a",
            TopicFilter::match_any(vec![t1, t2]).unwrap(),
            None,
        )]);

        let matches = subs.matching(&[batch_entry(0xaa, vec![t1, t2])]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.len(), 1);
    }

    #[test]
    fn remove_cleans_up_every_filter() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);
        subs.add_filter("a", TopicFilter::match_any(vec![t2]).unwrap())
            .unwrap();
        subs.add_filter("a", TopicFilter::Any).unwrap();

        assert!(subs.remove("a"));
        assert!(subs.is_empty());
        // Neither the topic entries nor the wildcard entry may survive.
        let matches = subs.matching(&[batch_entry(0xaa, vec![t1]), batch_entry(0xbb, vec![t2])]);
        assert!(matches.is_empty());
    }

    #[test]
    fn affinity_covers_every_filter_of_a_subscription() {
        let config = test_config();
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);
        subs.add_filter("a", TopicFilter::match_any(vec![t2]).unwrap())
            .unwrap();

        let filter = subs.build_combined_affinity_filter(&config);
        assert!(filter.contains(&t1));
        assert!(filter.contains(&t2));
    }

    #[test]
    fn affinity_matches_all_when_one_filter_is_any() {
        let config = test_config();
        let t1 = [1u8; 32];
        let mut subs =
            make_subscriptions(vec![("a", TopicFilter::match_any(vec![t1]).unwrap(), None)]);
        subs.add_filter("a", TopicFilter::Any).unwrap();

        let filter = subs.build_combined_affinity_filter(&config);
        assert!(filter.contains(&[99u8; 32]));
    }
}
