// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Header-only JAM synchronization with verified GRANDPA root advancement.
//!
//! Memory is bounded: the header tree and its rebuild copy share [`TREE_BYTES`]
//! and hold at most 4096 headers, a response is at most [`FRAME_BYTES`], each
//! connection keeps at most [`REPAIR_LIMIT`] repair headers and as many
//! announcements, and at most [`MAX_SUBSCRIBERS`] subscriber queues hold at
//! most 1 MiB each.

use super::{BlockNotification, Notification, SubscribeAll};
use crate::{
    jam_webtransport_cert::{P256PeerId, P256PeerIdParseError},
    platform::PlatformRef,
};
use alloc::{string::String, sync::Arc, vec::Vec};
use connection::peer_loop;
use core::{net::IpAddr, num::NonZeroUsize, time::Duration};
use futures_lite::{StreamExt as _, future};
use smoldot::jam::{
    chain_spec::{self, JamChainSpec},
    finality::{self, AuthoritySet},
    params::Params,
    state::{LightState, StateError},
    tree::{self, HeaderTree},
    types::{GenesisLightState, Hash, Header},
    verify::verified_genesis,
};

const TREE_BYTES: usize = 16 * 1024 * 1024;
const FRAME_BYTES: usize = 1024 * 1024;
const REPAIR_LIMIT: usize = 8;
const MAX_SUBSCRIBERS: usize = 8;
const MAX_PEERS: usize = 2;
const TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Why a JAM chain cannot be added.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ConfigError {
    /// The chain specification is larger than 16 MiB.
    #[display("chain specification exceeds 16 MiB")]
    SpecTooLarge,
    /// The chain specification is invalid.
    #[display("{_0}")]
    Spec(chain_spec::Error),
    /// The `bootnodes_p256` entry at `index` is not a P-256 curve point.
    #[display("JAM P256 identity of bootnodes_p256 entry {index}: {source:?}")]
    P256Identity {
        index: usize,
        source: P256PeerIdParseError,
    },
    /// The trusted starting state is invalid.
    #[display("JAM starting state: {_0:?}")]
    StartingState(StateError),
    /// The protocol parameters need more memory than the driver's budget.
    #[display("JAM trusted parameters exceed memory budget")]
    MemoryBudget,
    /// The trusted anchor does not fit in the header tree.
    #[display("JAM trusted anchor exceeds tree budget")]
    AnchorExceedsTreeBudget,
    /// The genesis header gives no valid GRANDPA authority set.
    #[display("JAM genesis finality: {_0}")]
    GenesisFinality(finality::Error),
    /// The chain is already used by too many clients.
    #[display("too many chain references")]
    TooManyReferences,
}

pub(crate) struct Config {
    params: Params,
    tree: HeaderTree,
    peers: Vec<Peer>,
    header_bytes: usize,
    authorities: AuthoritySet,
    max_blocks: usize,
}

struct Peer {
    identity: P256PeerId,
    ip: IpAddr,
    port: u16,
}

impl Config {
    pub(crate) fn from_spec(spec: &JamChainSpec) -> Result<Self, ConfigError> {
        let params = spec.params().clone();
        let (header_bytes, limits) = memory_limits(&params)?;
        let max_blocks = limits.max_blocks;
        let (header, raw_state) = spec.checkpoint().map_or(
            (spec.genesis_header(), spec.genesis_light_state()),
            |checkpoint| (&checkpoint.header, &checkpoint.state),
        );
        let state = Self::anchor_state(&params, raw_state)?;
        let authorities = match spec.checkpoint() {
            Some(checkpoint) => checkpoint.finality.clone(),
            None => {
                AuthoritySet::from_genesis(&params, header).map_err(ConfigError::GenesisFinality)?
            }
        };
        let mut peers = Vec::new();
        for (index, node) in spec.boot_nodes().enumerate() {
            let identity = P256PeerId::from_text(&node.p256_id_text)
                .map_err(|source| ConfigError::P256Identity { index, source })?;
            if peers.len() < MAX_PEERS {
                peers.push(Peer {
                    identity,
                    ip: node.ip,
                    port: node.port,
                });
            }
        }
        let root = verified_genesis(&params, header.clone(), state);
        let tree = HeaderTree::new(params.clone(), root, limits)
            .map_err(|_| ConfigError::AnchorExceedsTreeBudget)?;
        Ok(Self {
            params,
            tree,
            peers,
            authorities,
            max_blocks: max_blocks.get(),
            header_bytes,
        })
    }

    fn anchor_state(
        params: &Params,
        raw_state: &GenesisLightState,
    ) -> Result<LightState, ConfigError> {
        let state =
            LightState::from_anchor(params, raw_state).map_err(ConfigError::StartingState)?;
        state.validate(params).map_err(ConfigError::StartingState)?;
        Ok(state)
    }
}

fn memory_limits(params: &Params) -> Result<(usize, tree::Config), ConfigError> {
    // Worst-case owned header and post-state allocations, including vector capacity
    // slack. Two complete trees cover the survivor copy the tree makes on eviction.
    let validators = usize::from(params.max_validators);
    let epoch = usize::try_from(params.epoch_len).map_err(|_| ConfigError::MemoryBudget)?;
    let header_bytes = epoch
        .checked_mul(80)
        .and_then(|n| n.checked_add(validators * 192 + 2048))
        .ok_or(ConfigError::MemoryBudget)?;
    let state_bytes = epoch
        .checked_mul(160)
        .and_then(|n| n.checked_add(validators * 256 + 2048))
        .ok_or(ConfigError::MemoryBudget)?;
    if header_bytes > FRAME_BYTES / 2 || state_bytes > TREE_BYTES / 8 {
        return Err(ConfigError::MemoryBudget);
    }
    // Reserve one worst-case epoch/state and header for verification; keep the
    // second-tree allowance while eviction rebuilds survivors.
    let max_bytes = (TREE_BYTES - header_bytes - state_bytes) / 2;
    let max_blocks = (max_bytes / (HeaderTree::node_overhead() + 297)).min(4096);
    let max_blocks = NonZeroUsize::new(max_blocks)
        .filter(|n| n.get() >= 2)
        .ok_or(ConfigError::MemoryBudget)?;
    Ok((
        header_bytes,
        tree::Config {
            max_blocks,
            max_bytes,
            max_epoch_records: NonZeroUsize::new(8).ok_or(ConfigError::MemoryBudget)?,
        },
    ))
}

struct State {
    tree: HeaderTree,
    params: Params,
    subscribers: Vec<async_channel::Sender<Notification>>,
    stopped: bool,
    header_bytes: usize,
    authorities: AuthoritySet,
    max_blocks: usize,
    /// A single shared proof reservation, deduplicated across peer drivers.
    proof_owner: Option<(usize, Hash)>,
    /// Attempted configured peers per retained target. Never grows beyond the tree.
    proof_attempts: Vec<(Hash, u8)>,
}

#[derive(Debug)]
enum InsertFailure {
    ResourceLimit,
    Tree(tree::InsertError),
}

impl State {
    /// Header bytes in the snapshot are canonical JAM encodings.
    fn subscribe(&mut self, buffer_size: usize, runtime_interest: bool) -> SubscribeAll {
        self.subscribers.retain(|s| !s.is_closed());
        let queue_limit = (1024 * 1024 / self.header_bytes).clamp(1, 16);
        let (tx, rx) = async_channel::bounded(buffer_size.clamp(1, queue_limit));
        if !runtime_interest && !self.stopped && self.subscribers.len() < MAX_SUBSCRIBERS {
            self.subscribers.push(tx);
        }
        SubscribeAll {
            finalized_block_scale_encoded_header: self.tree.finalized().encoded().to_vec(),
            finalized_block_runtime: None,
            non_finalized_blocks_ancestry_order: self
                .tree
                .ancestry_order()
                .skip(1)
                .map(|b| BlockNotification {
                    is_new_best: b.hash() == self.tree.best().hash(),
                    scale_encoded_header: b.encoded().to_vec(),
                    parent_hash: b.parent(),
                })
                .collect(),
            new_blocks: rx,
        }
    }

    /// Reports a new block to subscribers with its canonical JAM encoding.
    fn insert(&mut self, header: Header, now: u64) -> Result<(), InsertFailure> {
        if self.stopped || header.encode(&self.params).len() > self.header_bytes {
            return Err(InsertFailure::ResourceLimit);
        }
        let hash = header.hash(&self.params);
        let result =
            self.tree
                .verify(header.parent, header, now)
                .and_then(|verified| match verified {
                    tree::VerifySuccess::Verified(verified) => self.tree.insert_verified(verified),
                    tree::VerifySuccess::AlreadyKnown => Ok(tree::Insert::AlreadyKnown),
                });
        match result {
            Ok(tree::Insert::AlreadyKnown) => Ok(()),
            Ok(tree::Insert::Inserted { evicted, .. }) => {
                if !evicted.is_empty() {
                    self.subscribers.clear();
                }
                if let Some(block) = self.tree.get(&hash) {
                    let notification = Notification::Block(BlockNotification {
                        is_new_best: self.tree.best().hash() == hash,
                        scale_encoded_header: block.encoded().to_vec(),
                        parent_hash: block.parent(),
                    });
                    self.subscribers
                        .retain(|tx| tx.try_send(notification.clone()).is_ok());
                }
                Ok(())
            }
            Err(tree::InsertError::Full) => {
                self.stopped = true;
                self.subscribers.clear();
                Err(InsertFailure::Tree(tree::InsertError::Full))
            }
            Err(error) => Err(InsertFailure::Tree(error)),
        }
    }
}

/// Handle to the header sync of a JAM chain. Subscriptions have the shape of a
/// Substrate [`SyncService`](super::SyncService)'s, and that is all it offers: the
/// driver dials its own peers, so there is no network service to query, and
/// JAM has no runtime and no Substrate peer or warp sync state.
pub(crate) struct JamSyncService {
    to_background: async_channel::Sender<SubscribeRequest>,
}

/// See [`JamSyncService::subscribe_all`].
struct SubscribeRequest {
    send_back: futures_channel::oneshot::Sender<SubscribeAll>,
    buffer_size: usize,
    runtime_interest: bool,
}

impl JamSyncService {
    /// Spawns the driver of the chain `config` describes.
    pub(crate) fn new<P: PlatformRef>(platform: P, log_name: String, config: Config) -> Self {
        let (to_background, from_foreground) = async_channel::bounded(16);
        platform.spawn_task(
            alloc::format!("jam-sync-{log_name}").into(),
            run(platform.clone(), log_name, config, from_foreground),
        );
        Self { to_background }
    }

    /// Like [`SyncService::subscribe_all`](super::SyncService::subscribe_all). A
    /// JAM chain has no runtime: with `runtime_interest`, the snapshot comes with
    /// a closed notification channel.
    pub(crate) async fn subscribe_all(
        &self,
        buffer_size: usize,
        runtime_interest: bool,
    ) -> SubscribeAll {
        let (send_back, rx) = futures_channel::oneshot::channel();
        self.to_background
            .send(SubscribeRequest {
                send_back,
                buffer_size,
                runtime_interest,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }
}

async fn run<P: PlatformRef>(
    platform: P,
    log_name: String,
    config: Config,
    rx: async_channel::Receiver<SubscribeRequest>,
) {
    let state = Arc::new(async_lock::Mutex::new(State {
        tree: config.tree,
        params: config.params.clone(),
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: config.header_bytes,
        authorities: config.authorities,
        max_blocks: config.max_blocks,
        proof_owner: None,
        proof_attempts: Vec::new(),
    }));
    let foreground = async {
        while let Ok(request) = rx.recv().await {
            let snapshot = state
                .lock()
                .await
                .subscribe(request.buffer_size, request.runtime_interest);
            let _ = request.send_back.send(snapshot);
        }
    };
    // Peer drivers must yield to the platform executor, not to a FuturesUnordered
    // that can immediately repoll the same child within one outer task poll.
    let (shutdown, cancelled) = async_channel::bounded::<()>(1);
    let mut peers_done = futures_util::stream::FuturesUnordered::new();
    for (peer_index, peer) in config.peers.into_iter().enumerate() {
        let (done, finished) = futures_channel::oneshot::channel();
        peers_done.push(finished);
        let platform_ref = platform.clone();
        let log_name = log_name.clone();
        let params = config.params.clone();
        let state = state.clone();
        let cancelled = cancelled.clone();
        platform.spawn_task(alloc::format!("jam-peer-{log_name}").into(), async move {
            future::or(
                peer_loop(&platform_ref, &log_name, &peer, peer_index, &params, state),
                async {
                    let _ = cancelled.recv().await;
                },
            )
            .await;
            let _ = done.send(());
        });
    }
    foreground.await;
    // Closing the sole sender cancels all drivers, including pending connect,
    // stream-opening, readiness and backoff waits. Await transport cleanup.
    drop(shutdown);
    while peers_done.next().await.is_some() {}
}

mod blocks;
mod connection;
mod grandpa;
mod log;

#[cfg(all(test, feature = "std"))]
mod tests;
