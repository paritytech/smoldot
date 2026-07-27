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

use core::sync::atomic::{AtomicU64, Ordering};

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

/// Success/failure counters of one network request protocol.
#[derive(Debug, Default)]
pub struct RequestMetrics {
    pub success: Counter,
    pub failure: Counter,
}

impl RequestMetrics {
    pub fn observe(&self, is_success: bool) {
        if is_success {
            self.success.inc();
        } else {
            self.failure.inc();
        }
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
