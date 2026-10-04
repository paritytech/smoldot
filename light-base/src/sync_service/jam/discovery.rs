// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Peer pool for the JAM driver: the chain spec's bootnodes plus the validators
//! of an active set `C(8)`. Until the first verified `C(8)` read, that set is
//! the chain spec's genesis `C(8)`; every read replaces it.
//!
//! A discovered peer is a liveness source only. It gets no privilege: every
//! header, block, justification and state proof it serves goes through the
//! same verification as a bootnode's. The pool only decides whom to dial.
//!
//! Bounds: at most [`MAX_BOOTNODES`] bootnodes and `max_discovered`
//! (`Params::max_validators`) discovered entries, plus at most one retired
//! entry per slot that is still held after leaving the set.
//!
//! Selection: a bootnode that no other slot holds and that is not in backoff,
//! else the genesis or discovered validator with the oldest failure (never
//! failed first),
//! else wait. Backoff is per candidate: a failed slot releases its candidate
//! and asks again, so it moves on at once instead of sleeping. Two slots never
//! hold the same Ed25519 identity.

use crate::jam_webtransport_cert::P256PeerId;
use alloc::vec::Vec;
use core::{fmt, net::IpAddr, time::Duration};
use smoldot::jam::{metadata::ValidatorEndpoint, types::Ed25519Public};

/// Number of slots the pool tracks; equal to the driver's connection count.
pub(super) const SLOTS: usize = super::MAX_PEERS;
/// Bootnodes taken from the chain spec, in order.
pub(super) const MAX_BOOTNODES: usize = 16;
/// Per-candidate reconnect backoff: 1 s doubling to 30 s, as the fixed-peer loop had.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A connection that lived this long resets its candidate's backoff to 1 s.
const LONG_LIVED: Duration = Duration::from_secs(60);
/// A bootnode that failed is retried in place of a working discovered peer
/// only after 30 s, doubling per failure up to 5 min, so a dead bootnode costs
/// at most one reconnect per interval.
const PREEMPT_FIRST: Duration = Duration::from_secs(30);
const PREEMPT_MAX: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// The chain spec's `bootnodes`.
    Bootnode,
    /// The chain spec's genesis `C(8)`, until the first verified read replaces it.
    Genesis,
    /// A verified `C(8)` read.
    Discovered,
}

impl Source {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Bootnode => "bootnode",
            Self::Genesis => "genesis",
            Self::Discovered => "discovered",
        }
    }
}

/// A dialable candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Peer {
    pub identity: P256PeerId,
    pub ip: IpAddr,
    pub port: u16,
    pub ed25519: Ed25519Public,
    pub source: Source,
}

impl Peer {
    /// A discovered candidate, or `None` when the record has no P-256 key, no
    /// port, or a key that is not a curve point.
    pub(super) fn discovered(endpoint: &ValidatorEndpoint) -> Option<Self> {
        if endpoint.port == 0 {
            return None;
        }
        let (x, y_odd) = endpoint.p256?;
        let identity = P256PeerId::from_parts(x, y_odd).ok()?;
        Some(Self {
            identity,
            ip: endpoint.ip,
            port: endpoint.port,
            ed25519: endpoint.ed25519,
            source: Source::Discovered,
        })
    }

    /// `ip:port`, IPv6 in brackets, for logs.
    pub(super) fn address(&self) -> Address {
        Address(self.ip, self.port)
    }
}

pub(super) struct Address(IpAddr, u16);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.1),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.1),
        }
    }
}

struct Entry {
    peer: Peer,
    failures: u32,
    last_failure: Option<Duration>,
    held_by: Option<usize>,
    /// Left the active set while held; removed when released.
    retired: bool,
    /// The platform cannot dial this address type.
    unsupported: bool,
}

impl Entry {
    fn new(peer: Peer) -> Self {
        Self {
            peer,
            failures: 0,
            last_failure: None,
            held_by: None,
            retired: false,
            unsupported: false,
        }
    }

    fn selectable(&self) -> bool {
        self.held_by.is_none() && !self.retired && !self.unsupported
    }

    fn ready_at(&self) -> Duration {
        self.after(backoff(self.failures))
    }

    fn after(&self, delay: Duration) -> Duration {
        self.last_failure
            .map_or(Duration::ZERO, |at| at.saturating_add(delay))
    }
}

fn backoff(failures: u32) -> Duration {
    match failures {
        0 => Duration::ZERO,
        n => Duration::from_secs(1u64 << (n - 1).min(5)).min(MAX_BACKOFF),
    }
}

fn preempt_delay(failures: u32) -> Duration {
    match failures {
        0 => Duration::ZERO,
        n => PREEMPT_FIRST
            .saturating_mul(1u32 << (n - 1).min(4))
            .min(PREEMPT_MAX),
    }
}

/// Result of asking for a candidate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Acquire {
    /// `cleared` is the bitmask of slots whose per-slot state (refusal bit,
    /// proof and read attempts) no longer describes the peer they will hold.
    Peer { peer: Peer, cleared: u8 },
    /// Nothing is dialable now. `Some` is the time until the earliest
    /// candidate leaves its backoff; `None` means the pool must change first.
    Wait(Option<Duration>),
}

/// How a slot gave its candidate back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Release {
    /// The attempt ended, after `lasted` (zero if it never connected).
    Ended { lasted: Duration },
    /// The platform cannot dial this address type; never select it again.
    Unsupported,
}

/// Outcome of a `C(8)` merge, for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Merge {
    /// Records in `C(8)`.
    pub validators: usize,
    /// Records with a port and a valid P-256 key.
    pub usable: usize,
    /// Discovered entries after the merge, excluding bootnode identities.
    pub discovered: usize,
    pub added: usize,
    pub removed: usize,
    /// Entries that left the set but stay until their slot releases them.
    pub retired: usize,
}

pub(super) struct Pool {
    /// Bootnodes first, then discovered entries.
    entries: Vec<Entry>,
    bootnodes: usize,
    max_discovered: usize,
    /// The identity each slot held last, held or not, for per-slot state.
    last: [Option<Ed25519Public>; SLOTS],
}

impl Pool {
    /// `bootnodes` keep their priority; `genesis` is the initial discovered
    /// set, deduplicated by Ed25519 identity against the bootnodes (a
    /// validator that is also a bootnode is one candidate, the bootnode) and
    /// bounded like any discovered set.
    pub(super) fn new(bootnodes: Vec<Peer>, genesis: Vec<Peer>, max_discovered: usize) -> Self {
        let mut entries: Vec<Entry> = Vec::new();
        for peer in bootnodes {
            if entries.len() < MAX_BOOTNODES
                && !entries.iter().any(|e| e.peer.ed25519 == peer.ed25519)
            {
                entries.push(Entry::new(Peer {
                    source: Source::Bootnode,
                    ..peer
                }));
            }
        }
        let bootnodes = entries.len();
        for peer in genesis {
            if entries.len() - bootnodes < max_discovered
                && !entries.iter().any(|e| e.peer.ed25519 == peer.ed25519)
            {
                entries.push(Entry::new(Peer {
                    source: Source::Genesis,
                    ..peer
                }));
            }
        }
        Self {
            bootnodes,
            entries,
            max_discovered,
            last: [None; SLOTS],
        }
    }

    pub(super) fn held(&self, slot: usize) -> Option<&Peer> {
        self.entries
            .iter()
            .find(|e| e.held_by == Some(slot))
            .map(|e| &e.peer)
    }

    pub(super) fn acquire(&mut self, slot: usize, now: Duration) -> Acquire {
        if slot >= SLOTS {
            return Acquire::Wait(None);
        }
        if let Some(peer) = self.held(slot) {
            return Acquire::Peer {
                peer: peer.clone(),
                cleared: 0,
            };
        }
        let ready = |e: &Entry| e.selectable() && e.ready_at() <= now;
        let index = self.entries[..self.bootnodes]
            .iter()
            .position(ready)
            .or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .skip(self.bootnodes)
                    .filter(|(_, e)| ready(e))
                    // `None` sorts first: a never-failed validator is the oldest failure.
                    .min_by_key(|(index, e)| (e.last_failure, *index))
                    .map(|(index, _)| index)
            });
        let Some(index) = index else {
            return Acquire::Wait(
                self.entries
                    .iter()
                    .filter(|e| e.selectable())
                    .map(|e| e.ready_at().saturating_sub(now))
                    .min(),
            );
        };
        self.entries[index].held_by = Some(slot);
        let peer = self.entries[index].peer.clone();
        let cleared = self.note_holder(slot, peer.ed25519);
        Acquire::Peer { peer, cleared }
    }

    /// Records that `slot` now holds `identity`; returns the slots whose
    /// per-slot state must be cleared.
    fn note_holder(&mut self, slot: usize, identity: Ed25519Public) -> u8 {
        let mut cleared = 0;
        for (other, last) in self.last.iter_mut().enumerate() {
            if (other == slot) != (*last == Some(identity)) {
                // This slot switches identity, or another slot's record of
                // this identity is now stale.
                cleared |= 1 << other;
            }
            if other != slot && *last == Some(identity) {
                *last = None;
            }
        }
        self.last[slot] = Some(identity);
        cleared
    }

    pub(super) fn release(&mut self, slot: usize, release: Release, now: Duration) {
        let Some(index) = self.entries.iter().position(|e| e.held_by == Some(slot)) else {
            return;
        };
        let entry = &mut self.entries[index];
        entry.held_by = None;
        match release {
            Release::Ended { lasted } => {
                entry.failures = if lasted >= LONG_LIVED {
                    1
                } else {
                    entry.failures.saturating_add(1)
                };
                entry.last_failure = Some(now);
            }
            Release::Unsupported => entry.unsupported = true,
        }
        if entry.retired {
            self.entries.remove(index);
        }
    }

    /// Moves `slot` from a genesis or discovered peer to a free bootnode whose retry
    /// interval has passed, so a restarted bootnode is used again. The old
    /// candidate is released without a failure. `None` leaves `slot` as is.
    pub(super) fn preempt(&mut self, slot: usize, now: Duration) -> Option<(Peer, u8)> {
        let current = self.entries.iter().position(|e| e.held_by == Some(slot))?;
        if current < self.bootnodes {
            return None;
        }
        let bootnode = self.entries[..self.bootnodes]
            .iter()
            .position(|e| e.selectable() && e.after(preempt_delay(e.failures)) <= now)?;
        self.entries[current].held_by = None;
        if self.entries[current].retired {
            // `current` is past every bootnode, so `bootnode` stays valid.
            self.entries.remove(current);
        }
        self.entries[bootnode].held_by = Some(slot);
        let peer = self.entries[bootnode].peer.clone();
        let cleared = self.note_holder(slot, peer.ed25519);
        Some((peer, cleared))
    }

    /// Replaces the discovered entries (genesis ones included) wholesale with
    /// one verified `C(8)` read. Bootnodes stay; identities that survive keep their failure
    /// record; a held identity that left the set is retired, not cut.
    pub(super) fn replace_discovered(
        &mut self,
        validators: usize,
        peers: impl IntoIterator<Item = Option<Peer>>,
    ) -> Merge {
        let mut merge = Merge {
            validators,
            ..Merge::default()
        };
        let mut old: Vec<Entry> = self.entries.drain(self.bootnodes..).collect();
        let mut next: Vec<Entry> = Vec::new();
        for peer in peers.into_iter().flatten() {
            merge.usable += 1;
            if next.len() >= self.max_discovered
                || self.entries.iter().any(|e| e.peer.ed25519 == peer.ed25519)
                || next.iter().any(|e| e.peer.ed25519 == peer.ed25519)
            {
                continue;
            }
            let entry = match old.iter().position(|e| e.peer.ed25519 == peer.ed25519) {
                Some(index) => {
                    let mut entry = old.swap_remove(index);
                    if entry.peer.ip != peer.ip || entry.peer.port != peer.port {
                        entry.unsupported = false;
                    }
                    entry.retired = false;
                    entry.peer = peer;
                    entry
                }
                None => {
                    merge.added += 1;
                    Entry::new(peer)
                }
            };
            next.push(entry);
        }
        merge.discovered = next.len();
        for mut entry in old {
            if entry.held_by.is_some() {
                entry.retired = true;
                merge.retired += 1;
                next.push(entry);
            } else if !entry.retired {
                merge.removed += 1;
            }
        }
        self.entries.extend(next);
        merge
    }

    #[cfg(test)]
    pub(super) fn entries(&self) -> impl Iterator<Item = (&Peer, Option<usize>, bool)> {
        self.entries.iter().map(|e| (&e.peer, e.held_by, e.retired))
    }
}

#[cfg(test)]
mod tests;
