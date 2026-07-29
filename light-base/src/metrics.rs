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
//! Counters and gauges are plain atomics incremented at the same places where the
//! corresponding events are logged. Reads and writes use relaxed ordering: metrics are
//! advisory and never synchronize other memory.

use alloc::{borrow::Cow, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use smoldot::json_rpc::methods;

/// Monotonically increasing counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Value that can go up and down.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
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
        self.0.load(Ordering::Relaxed)
    }
}

/// Success/failure counters and total duration of one network request protocol.
#[derive(Debug, Default)]
pub struct RequestMetrics {
    pub success: Counter,
    pub failure: Counter,
    pub duration_us: Counter,
}

impl RequestMetrics {
    pub fn observe(&self, is_success: bool, duration: core::time::Duration) {
        if is_success {
            self.success.inc();
        } else {
            self.failure.inc();
        }
        self.duration_us
            .add(u64::try_from(duration.as_micros()).unwrap_or(u64::MAX));
    }
}

/// Metrics of the network service. One instance per process, shared between all chains.
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    pub connections_started: Counter,
    pub connections_handshakes_finished: Counter,
    pub connections_shutdowns: Counter,
    pub discovery_addresses_dropped: Counter,
}

/// Per-chain metrics. One instance per chain, shared between all the services of that chain.
#[derive(Debug, Default)]
pub struct ChainMetrics {
    pub blocks_requests: RequestMetrics,
    pub warp_sync_requests: RequestMetrics,
    pub storage_proof_requests: RequestMetrics,
    pub call_proof_requests: RequestMetrics,
    pub peer_bans: Counter,
    pub gossip_peers_connected: Gauge,

    pub sync_blocks_verified: Counter,
    pub sync_block_verify_errors: Counter,
    pub sync_finality_proofs_verified: Counter,
    pub sync_finality_proof_verify_errors: Counter,
    pub sync_warp_fragments_verified: Counter,
    pub sync_best_block_height: Gauge,
    pub sync_finalized_block_height: Gauge,

    pub runtime_compilations: Counter,
    pub runtime_compilation_errors: Counter,
    pub runtime_compilation_time_us: Counter,
    pub runtime_cache_hits: Counter,

    pub transactions_dropped: Counter,
    pub json_rpc_requests: Counter,
}

impl ChainMetrics {
    pub fn observe_runtime_compilation(&self, duration: core::time::Duration, is_success: bool) {
        self.runtime_compilations.inc();
        if !is_success {
            self.runtime_compilation_errors.inc();
        }
        self.runtime_compilation_time_us
            .add(u64::try_from(duration.as_micros()).unwrap_or(u64::MAX));
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
        ("warpSync", &chain.warp_sync_requests),
        ("storageProof", &chain.storage_proof_requests),
        ("callProof", &chain.call_proof_requests),
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
            value: metrics.duration_us.get() as f64 / 1_000_000.0,
        })
        .collect::<Vec<_>>();

    let metrics = alloc::vec![
        counter(
            "networkConnectionsStartedTotal",
            network.connections_started.get()
        ),
        counter(
            "networkConnectionsHandshakesFinishedTotal",
            network.connections_handshakes_finished.get()
        ),
        counter(
            "networkConnectionsShutdownsTotal",
            network.connections_shutdowns.get()
        ),
        counter(
            "networkDiscoveryAddressesDroppedTotal",
            network.discovery_addresses_dropped.get()
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
        counter("networkPeerBansTotal", chain.peer_bans.get()),
        gauge(
            "networkGossipPeersConnected",
            chain.gossip_peers_connected.get()
        ),
        counter("syncBlocksVerifiedTotal", chain.sync_blocks_verified.get()),
        counter(
            "syncBlockVerifyErrorsTotal",
            chain.sync_block_verify_errors.get()
        ),
        counter(
            "syncFinalityProofsVerifiedTotal",
            chain.sync_finality_proofs_verified.get()
        ),
        counter(
            "syncFinalityProofVerifyErrorsTotal",
            chain.sync_finality_proof_verify_errors.get()
        ),
        counter(
            "syncWarpFragmentsVerifiedTotal",
            chain.sync_warp_fragments_verified.get()
        ),
        gauge("syncBestBlockHeight", chain.sync_best_block_height.get()),
        gauge(
            "syncFinalizedBlockHeight",
            chain.sync_finalized_block_height.get()
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
                value: chain.runtime_compilation_time_us.get() as f64 / 1_000_000.0,
            }],
        },
        counter("runtimeCacheHitsTotal", chain.runtime_cache_hits.get()),
        counter("transactionsDroppedTotal", chain.transactions_dropped.get()),
        counter("jsonrpcRequestsTotal", chain.json_rpc_requests.get()),
    ];

    methods::MetricsSnapshot { metrics }
}
