// Smoldot
// Copyright (C) 2025  Parity Technologies (UK) Ltd.
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

//! Internal metrics, exposed through the `sudo_unstable_metrics` JSON-RPC function.
//!
//! See <https://github.com/paritytech/smoldot/issues/3285>.
//!
//! Counters and gauges are plain relaxed atomics: metrics are advisory and never
//! synchronize other memory.

use crate::{
    network_service::{BanReason, DiscoveredAddressDropReason},
    transactions_service::DropReasonKind,
};
use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap, vec::Vec};
use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};
use smoldot::json_rpc::methods;
use strum::IntoEnumIterator;

// 32-bit atomics so that the metrics also compile on targets without 64-bit
// atomics (e.g. `thumbv7m-none-eabi`); durations are tracked in milliseconds
// to make the range acceptable.

/// Monotonically increasing counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU32);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0
            .fetch_add(u32::try_from(n).unwrap_or(u32::MAX), Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        u64::from(self.0.load(Ordering::Relaxed))
    }
}

/// Value that can go up and down.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU32);

impl Gauge {
    pub fn set(&self, value: u64) {
        self.0
            .store(u32::try_from(value).unwrap_or(u32::MAX), Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    pub fn get(&self) -> u64 {
        u64::from(self.0.load(Ordering::Relaxed))
    }
}

/// Success/failure counters and total duration of one network request protocol.
#[derive(Debug, Default)]
pub struct RequestMetrics {
    pub success: Counter,
    pub failure: Counter,
    pub duration_ms: Counter,
}

impl RequestMetrics {
    pub fn observe(&self, is_success: bool, duration: core::time::Duration) {
        if is_success {
            self.success.inc();
        } else {
            self.failure.inc();
        }
        self.duration_ms
            .add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }
}

/// Metric label: a fieldless enum whose variants are the label values.
///
/// Implemented through strum derives:
/// - `EnumIter` enumerates all label values, so a snapshot reports every one of them,
///   including zero counts;
/// - `IntoStaticStr` turns each variant name into its label string;
/// - `#[strum(serialize_all = "kebab-case")]` sets the casing of those strings;
/// - for enums with payloads, derive `strum::EnumDiscriminants` and use the generated
///   payload-free enum as the label, since label values must be plain strings;
/// - variants marked `#[strum(disabled)]` are excluded from the metric:
///   [`LabeledCounter::inc`] silently ignores them.
pub trait MetricLabel: IntoEnumIterator + Into<&'static str> + PartialEq {}
impl<T: IntoEnumIterator + Into<&'static str> + PartialEq> MetricLabel for T {}

/// Counter broken down by the variants of `L`.
pub struct LabeledCounter<L: MetricLabel> {
    counters: Box<[Counter]>,
    marker: PhantomData<fn(&L)>,
}

impl<L: MetricLabel> LabeledCounter<L> {
    pub fn inc(&self, value: impl Into<L>) {
        let value = value.into();
        // A value absent from the iterator is a `#[strum(disabled)]` variant: not counted.
        if let Some(position) = L::iter().position(|v| v == value) {
            self.counters[position].inc();
        }
    }
}

impl<L: MetricLabel> Default for LabeledCounter<L> {
    fn default() -> Self {
        LabeledCounter {
            counters: L::iter().map(|_| Counter::default()).collect(),
            marker: PhantomData,
        }
    }
}

impl<L: MetricLabel> fmt::Debug for LabeledCounter<L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(
                L::iter()
                    .map(Into::into)
                    .zip(self.counters.iter().map(Counter::get)),
            )
            .finish()
    }
}

/// Metrics of the network service. One instance per process, shared between all chains.
///
/// The connection counters are transport-agnostic (TCP, WebSocket, WebRTC) and count
/// connections, not peers. The light client never listens, so all connections are outbound.
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    /// Dial attempts, no matter the result.
    pub connections_dialed: Counter,
    /// Subset of [`NetworkMetrics::connections_dialed`] that completed the libp2p handshake.
    pub connections_handshakes_finished: Counter,
    /// Connections closed, whether or not the handshake had finished.
    pub connections_shutdowns: Counter,
    /// Addresses obtained through discovery and discarded instead of stored.
    pub(crate) discovery_addresses_dropped: LabeledCounter<DiscoveredAddressDropReason>,
}

/// Per-chain metrics. One instance per chain, shared between all the services of that chain.
#[derive(Debug, Default)]
pub struct ChainMetrics {
    pub blocks_requests: RequestMetrics,
    pub warp_sync_requests: RequestMetrics,
    pub storage_proof_requests: RequestMetrics,
    /// Child trie storage proof requests. Sent over the same wire protocol as
    /// [`ChainMetrics::storage_proof_requests`], but counted separately.
    pub child_storage_proof_requests: RequestMetrics,
    pub call_proof_requests: RequestMetrics,
    pub peer_bans: LabeledCounter<BanReason>,
    pub gossip_peers_connected: Gauge,

    pub sync_blocks_verified: Counter,
    pub sync_block_verify_errors: Counter,
    pub sync_finality_proofs_verified: Counter,
    pub sync_finality_proof_verify_errors: Counter,
    pub sync_warp_fragments_verified: Counter,
    pub sync_best_block_height: Gauge,
    pub sync_finalized_block_height: Gauge,
    pub sync_warp_sync_height: Gauge,
    pub sync_warp_sync_target_height: Gauge,

    pub runtime_compilations: Counter,
    pub runtime_compilation_errors: Counter,
    pub runtime_compilation_time_ms: Counter,
    pub runtime_cache_hits: Counter,

    pub transactions_dropped: LabeledCounter<DropReasonKind>,
    pub json_rpc_requests: Counter,
}

impl ChainMetrics {
    pub fn observe_runtime_compilation(&self, duration: core::time::Duration, is_success: bool) {
        self.runtime_compilations.inc();
        if !is_success {
            self.runtime_compilation_errors.inc();
        }
        self.runtime_compilation_time_ms
            .add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }
}

fn labels(
    entries: &[(&'static str, &'static str)],
) -> BTreeMap<Cow<'static, str>, Cow<'static, str>> {
    entries
        .iter()
        .map(|(k, v)| (Cow::Borrowed(*k), Cow::Borrowed(*v)))
        .collect()
}

fn entry(labels_list: &[(&'static str, &'static str)], value: u64) -> methods::MetricEntry {
    methods::MetricEntry {
        labels: labels(labels_list),
        value: value as f64,
    }
}

fn counter(name: &'static str, value: u64) -> methods::Metric {
    methods::Metric {
        name: Cow::Borrowed(name),
        ty: methods::MetricType::Counter,
        entries: alloc::vec![methods::MetricEntry {
            labels: BTreeMap::new(),
            value: value as f64,
        }],
    }
}

fn labeled_counter<L: MetricLabel>(
    name: &'static str,
    label_key: &'static str,
    counter: &LabeledCounter<L>,
) -> methods::Metric {
    methods::Metric {
        name: Cow::Borrowed(name),
        ty: methods::MetricType::Counter,
        entries: L::iter()
            .map(Into::into)
            .zip(counter.counters.iter())
            .map(|(label, counter)| entry(&[(label_key, label)], counter.get()))
            .collect(),
    }
}

fn gauge(name: &'static str, value: u64) -> methods::Metric {
    methods::Metric {
        name: Cow::Borrowed(name),
        ty: methods::MetricType::Gauge,
        entries: alloc::vec![methods::MetricEntry {
            labels: BTreeMap::new(),
            value: value as f64,
        }],
    }
}

/// Builds the response to `sudo_unstable_metrics` out of the process-wide network metrics and
/// the metrics of the chain the JSON-RPC client is connected to.
pub fn snapshot(network: &NetworkMetrics, chain: &ChainMetrics) -> methods::MetricsSnapshot {
    let request_protocols = [
        ("blocks", &chain.blocks_requests),
        ("warp-sync", &chain.warp_sync_requests),
        ("storage-proof", &chain.storage_proof_requests),
        ("child-storage-proof", &chain.child_storage_proof_requests),
        ("call-proof", &chain.call_proof_requests),
    ];

    let requests_entries = request_protocols
        .into_iter()
        .flat_map(|(protocol, metrics)| {
            [
                methods::MetricEntry {
                    labels: labels(&[("protocol", protocol), ("outcome", "success")]),
                    value: metrics.success.get() as f64,
                },
                methods::MetricEntry {
                    labels: labels(&[("protocol", protocol), ("outcome", "failure")]),
                    value: metrics.failure.get() as f64,
                },
            ]
        })
        .collect::<Vec<_>>();

    let requests_duration_entries = request_protocols
        .into_iter()
        .map(|(protocol, metrics)| methods::MetricEntry {
            labels: labels(&[("protocol", protocol)]),
            value: metrics.duration_ms.get() as f64 / 1_000.0,
        })
        .collect::<Vec<_>>();

    let metrics = alloc::vec![
        counter(
            "networkConnectionsDialedTotal",
            network.connections_dialed.get()
        ),
        counter(
            "networkConnectionsHandshakesFinishedTotal",
            network.connections_handshakes_finished.get()
        ),
        counter(
            "networkConnectionsShutdownsTotal",
            network.connections_shutdowns.get()
        ),
        labeled_counter(
            "networkDiscoveryAddressesDroppedTotal",
            "reason",
            &network.discovery_addresses_dropped,
        ),
        methods::Metric {
            name: Cow::Borrowed("networkRequestsTotal"),
            ty: methods::MetricType::Counter,
            entries: requests_entries,
        },
        methods::Metric {
            name: Cow::Borrowed("networkRequestSecondsTotal"),
            ty: methods::MetricType::Counter,
            entries: requests_duration_entries,
        },
        labeled_counter("networkPeerBansTotal", "reason", &chain.peer_bans),
        gauge(
            "networkGossipPeersConnected",
            chain.gossip_peers_connected.get()
        ),
        methods::Metric {
            name: Cow::Borrowed("syncBlocksVerifiedTotal"),
            ty: methods::MetricType::Counter,
            entries: alloc::vec![
                entry(&[("outcome", "success")], chain.sync_blocks_verified.get()),
                entry(
                    &[("outcome", "failure")],
                    chain.sync_block_verify_errors.get(),
                ),
            ],
        },
        methods::Metric {
            name: Cow::Borrowed("syncFinalityProofsVerifiedTotal"),
            ty: methods::MetricType::Counter,
            entries: alloc::vec![
                entry(
                    &[("outcome", "success")],
                    chain.sync_finality_proofs_verified.get(),
                ),
                entry(
                    &[("outcome", "failure")],
                    chain.sync_finality_proof_verify_errors.get(),
                ),
            ],
        },
        counter(
            "syncWarpFragmentsVerifiedTotal",
            chain.sync_warp_fragments_verified.get()
        ),
        gauge("syncBestBlockHeight", chain.sync_best_block_height.get()),
        gauge(
            "syncFinalizedBlockHeight",
            chain.sync_finalized_block_height.get()
        ),
        gauge("syncWarpSyncHeight", chain.sync_warp_sync_height.get()),
        gauge(
            "syncWarpSyncTargetHeight",
            chain.sync_warp_sync_target_height.get()
        ),
        counter("runtimeCompilationsTotal", chain.runtime_compilations.get()),
        counter(
            "runtimeCompilationErrorsTotal",
            chain.runtime_compilation_errors.get()
        ),
        methods::Metric {
            name: Cow::Borrowed("runtimeCompilationSecondsTotal"),
            ty: methods::MetricType::Counter,
            entries: alloc::vec![methods::MetricEntry {
                labels: BTreeMap::new(),
                value: chain.runtime_compilation_time_ms.get() as f64 / 1_000.0,
            }],
        },
        counter("runtimeCacheHitsTotal", chain.runtime_cache_hits.get()),
        labeled_counter(
            "transactionsDroppedTotal",
            "reason",
            &chain.transactions_dropped,
        ),
        counter("jsonrpcRequestsTotal", chain.json_rpc_requests.get()),
    ];

    methods::MetricsSnapshot { metrics }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transactions_dropped_labels() {
        let labels = DropReasonKind::iter()
            .map(<&'static str>::from)
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            [
                "gap-in-chain",
                "max-pending-transactions-reached",
                "invalid",
                "validate-error"
            ]
        );
    }

    #[test]
    fn peer_ban_labels() {
        let labels = BanReason::iter()
            .map(<&'static str>::from)
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            [
                "bad-block",
                "bad-block-announce",
                "bad-child-trie-root",
                "bad-grandpa-commit",
                "bad-justification",
                "bad-merkle-proof",
                "bad-warp-sync-fragment",
                "invalid-call-proof",
                "blocks-request-failed",
                "call-proof-request-failed",
                "child-storage-request-failed",
                "storage-request-failed",
                "warp-sync-request-failed"
            ]
        );
    }

    #[test]
    fn discovered_address_drop_labels() {
        let labels = DiscoveredAddressDropReason::iter()
            .map(<&'static str>::from)
            .collect::<Vec<_>>();
        assert_eq!(labels, ["peer-id-mismatch", "not-supported", "invalid"]);
    }

    #[test]
    fn disabled_variants_not_counted() {
        let counter = LabeledCounter::<DropReasonKind>::default();
        counter.inc(&crate::transactions_service::DropReason::Crashed);
        counter.inc(&crate::transactions_service::DropReason::GapInChain);
        let entries = labeled_counter("test", "reason", &counter).entries;
        assert_eq!(entries.len(), 4);
        assert_eq!(entries.iter().map(|e| e.value).sum::<f64>(), 1.0);
    }
}
