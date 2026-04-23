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
use core::num::NonZero;
use smoldot::json_rpc::methods::{StatementSubmitResult, TopicFilter};
use smoldot::network::codec;

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
            reason: "Invalid statement encoding".into(),
        };
    }

    let broadcasted = broadcast(encoded.to_vec()).await;
    if broadcasted.total == 0 {
        StatementSubmitResult::InternalError {
            error: "No connected peers".into(),
        }
    } else {
        StatementSubmitResult::New
    }
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

pub(super) fn build_combined_affinity_filter(
    subscriptions: &hashbrown::HashMap<String, StatementSubscription, fnv::FnvBuildHasher>,
    config: &network_service::StatementProtocolConfig,
) -> network_service::AffinityFilter {
    let mut all_topics: Vec<&[u8; 32]> = Vec::new();

    for sub in subscriptions.values() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;
    use core::time::Duration;
    use futures_lite::future::block_on;

    const SEED: u128 = 0x5EED_5EED_5EED_5EED_5EED_5EED_5EED_5EED;
    const FPR: f64 = 0.01;

    fn test_config() -> network_service::StatementProtocolConfig {
        network_service::StatementProtocolConfig::new(
            NonZero::new(128).unwrap(),
            FPR,
            SEED,
            Duration::from_secs(1),
        )
    }

    fn make_subscriptions(
        entries: Vec<(&str, TopicFilter, Option<NonZero<usize>>)>,
    ) -> hashbrown::HashMap<String, StatementSubscription, fnv::FnvBuildHasher> {
        let mut map = hashbrown::HashMap::with_hasher(fnv::FnvBuildHasher::default());
        for (id, filter, max_seen) in entries {
            map.insert(id.to_string(), StatementSubscription::new(filter, max_seen));
        }
        map
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

    #[test]
    fn validate_and_broadcast_invalid_encoding() {
        let result = block_on(validate_and_broadcast_statement(&[0xff, 0xff], |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            StatementSubmitResult::Invalid {
                reason: "Invalid statement encoding".into()
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
                error: "No connected peers".into()
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
        let filter = build_combined_affinity_filter(&subs, &config);

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
        let filter = build_combined_affinity_filter(&subs, &config);

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
        let filter = build_combined_affinity_filter(&subs, &config);

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
}
