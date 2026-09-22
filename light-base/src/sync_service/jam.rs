// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Header-only JAM synchronization with verified GRANDPA root advancement.
//!
//! Resource accounting (estimates, not a process/allocator peak measurement):
//! the tree and its verification/rebuild copies share 16 MiB. Each of two peers
//! retains at most eight repair headers and eight announcements (at most
//! 8 MiB together at the maximum accepted header budget). Allow 16 MiB per peer
//! for B2 frames, decoded events and bounded I/O staging, including one decoded
//! CE128 batch capped at 1 MiB of wire bytes (owned header allocations are
//! bounded by their wire lengths and Params). Adaptive requests grow from one
//! to 64 blocks within that cap. Eight subscriber queues add at most 1 MiB each.
//! Another 4 MiB covers the single shared proof, decoded witnesses, verifier
//! scratch space, current/next authorities and transition copies. At most 512
//! attempted-target records add less than 32 KiB. The conservative chain-task
//! allowance is approximately 76 MiB (rounded up separately for those records).
//! One RPC frontend separately allows two 4 MiB pin maps, a temporary snapshot
//! below 8 MiB, 16 responses (each below about 1 MiB), and 32 64-KiB requests:
//! allow another 36 MiB including collection/staging overhead. Additional
//! frontends cost additional memory; these are not a global client limit.
//! Platform-owned transport buffers, allocator metadata, executable/VM memory
//! and the bounded 16-MiB chain-spec parsing input are outside these estimates.
//! The external fixture test reports retained inline/vector-capacity bytes;
//! it deliberately does not label this as a measured total heap peak.

use super::{BlockNotification, Notification, SubscribeAll, SyncStatus, ToBackground};
use crate::{
    jam_webtransport_cert::{self, P256PeerId},
    log,
    platform::{MultiStreamAddress, PlatformRef, SubstreamDirection},
};
use alloc::{borrow::Cow, boxed::Box, collections::VecDeque, string::String, sync::Arc, vec::Vec};
use core::{net::IpAddr, num::NonZeroUsize, pin::Pin, time::Duration};
use futures_lite::{StreamExt as _, future};
use smoldot::jam::{
    chain_spec::JamChainSpec,
    finality::{self, AuthoritySet, Justification},
    net,
    params::Params,
    state::LightState,
    tree::{self, HeaderTree},
    types::{BlockRequest, Direction, Final, GenesisLightState, Handshake, Hash, Header},
    verify::verified_genesis,
};

const TREE_BYTES: usize = 16 * 1024 * 1024;
const FRAME_BYTES: usize = 1024 * 1024;
const REPAIR_LIMIT: usize = 8;
const MAX_SUBSCRIBERS: usize = 8;
const MAX_PEERS: usize = 2;
const TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

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
    pub(crate) fn from_spec(spec: &JamChainSpec) -> Result<Self, String> {
        let params = spec.params().clone();
        let (header_bytes, max_blocks) = memory_limits(&params)?;
        let (header, raw_state) = spec.checkpoint().map_or(
            (spec.genesis_header(), spec.genesis_light_state()),
            |checkpoint| (&checkpoint.header, &checkpoint.state),
        );
        let state = Self::anchor_state(&params, raw_state)?;
        let authorities = match spec.checkpoint() {
            Some(checkpoint) => checkpoint.finality.clone(),
            None => AuthoritySet::from_genesis(&params, header)
                .map_err(|e| alloc::format!("JAM genesis finality: {e}"))?,
        };
        let mut peers = Vec::new();
        for node in spec.boot_nodes() {
            if let Some(p256_id_text) = node.p256_id_text {
                let identity = P256PeerId::from_text(&p256_id_text)
                    .map_err(|e| alloc::format!("JAM P256 identity: {e:?}"))?;
                if peers.len() < MAX_PEERS {
                    peers.push(Peer {
                        identity,
                        ip: node.ip,
                        port: node.port,
                    });
                }
            }
        }
        let root = verified_genesis(&params, header.clone(), state);
        let tree = HeaderTree::new(params.clone(), root, tree::Config { max_blocks });
        Ok(Self {
            params,
            tree,
            peers,
            authorities,
            max_blocks: max_blocks.get(),
            header_bytes,
        })
    }

    fn anchor_state(params: &Params, raw_state: &GenesisLightState) -> Result<LightState, String> {
        let state = LightState::from_anchor(params, raw_state)
            .map_err(|e| alloc::format!("JAM starting state: {e:?}"))?;
        state
            .validate(params)
            .map_err(|e| alloc::format!("JAM starting state: {e:?}"))?;
        Ok(state)
    }
}

fn memory_limits(params: &Params) -> Result<(usize, NonZeroUsize), String> {
    // Worst-case owned header and post-state allocations, including vector capacity
    // slack. Two complete trees cover B4's transient survivor cloning on eviction.
    let validators = usize::from(params.max_validators);
    let epoch =
        usize::try_from(params.epoch_len).map_err(|_| String::from("JAM epoch too large"))?;
    let header_bytes = epoch
        .checked_mul(80)
        .and_then(|n| n.checked_add(validators * 192 + 2048))
        .ok_or_else(|| String::from("JAM header budget overflow"))?;
    let state_bytes = epoch
        .checked_mul(160)
        .and_then(|n| n.checked_add(validators * 256 + 2048))
        .ok_or_else(|| String::from("JAM state budget overflow"))?;
    if header_bytes > FRAME_BYTES / 2 || state_bytes > TREE_BYTES / 8 {
        return Err(String::from("JAM trusted parameters exceed memory budget"));
    }
    // Three extra nodes cover verification temporaries alongside both retained trees.
    let max_blocks =
        ((TREE_BYTES / (header_bytes + state_bytes + 1024)).saturating_sub(3) / 2).min(512);
    let max_blocks = NonZeroUsize::new(max_blocks)
        .filter(|n| n.get() >= 2)
        .ok_or_else(|| String::from("JAM tree budget too small"))?;
    Ok((header_bytes, max_blocks))
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
    fn proof_limits(&self) -> finality::Limits {
        finality::Limits {
            max_bytes: FRAME_BYTES,
            max_ancestry_headers: (FRAME_BYTES / self.header_bytes).max(1),
            max_ancestry_steps: self
                .max_blocks
                .saturating_mul(usize::from(self.params.max_validators))
                .saturating_mul(2),
        }
    }

    /// Select an authenticated target, stopping at the first unfinalized epoch
    /// mark. Advertisements trigger fetching but never supply authority state.
    fn reserve_proof(&mut self, peer: usize, advertised: &Final) -> Option<Hash> {
        if self.stopped
            || self.proof_owner.is_some()
            || advertised.slot <= self.tree.finalized().slot
        {
            return None;
        }
        let tip = self
            .tree
            .get(&advertised.hash)
            .unwrap_or_else(|| self.tree.best());
        let path: Vec<_> = self
            .tree
            .ancestors(&tip.hash)
            .take_while(|b| b.hash != self.tree.finalized().hash)
            .collect();
        let candidate = path
            .iter()
            .rev()
            .find(|b| b.header.epoch_mark.is_some())
            .copied()
            .or_else(|| path.first().copied())?;
        if candidate.slot > advertised.slot {
            return None;
        }
        let target = candidate.hash;
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash
        });
        let bit = 1u8 << peer;
        if let Some((_, attempts)) = self
            .proof_attempts
            .iter_mut()
            .find(|(hash, _)| *hash == target)
        {
            if *attempts & bit != 0 {
                return None;
            }
            *attempts |= bit;
        } else {
            self.proof_attempts.push((target, bit));
        }
        self.proof_owner = Some((peer, target));
        Some(target)
    }

    fn finalize(&mut self, target: Hash, bytes: &[u8]) -> Result<(), finality::Error> {
        let limits = self.proof_limits();
        let proof = Justification::decode(&self.params, bytes, limits)?;
        let verified = proof.verify(
            &self.params,
            self.authorities.set_id(),
            self.authorities.current(),
            &target,
            limits,
            |hash| self.tree.get(hash).map(|b| &b.header),
        )?;
        let result = self.tree.finalize(&verified, &mut self.authorities)?;
        if result.finalized.is_empty() {
            return Ok(());
        }
        let notification = Notification::Finalized {
            finalized_blocks_hashes: result.finalized,
            pruned_blocks: result.pruned,
            best_block_hash_if_changed: result.best_changed.then(|| self.tree.best().hash),
        };
        self.subscribers
            .retain(|tx| tx.try_send(notification.clone()).is_ok());
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash
        });
        Ok(())
    }

    fn subscribe(&mut self, buffer_size: usize, runtime_interest: bool) -> SubscribeAll {
        self.subscribers.retain(|s| !s.is_closed());
        let queue_limit = (1024 * 1024 / self.header_bytes).clamp(1, 16);
        let (tx, rx) = async_channel::bounded(buffer_size.clamp(1, queue_limit));
        if !runtime_interest && !self.stopped && self.subscribers.len() < MAX_SUBSCRIBERS {
            self.subscribers.push(tx);
        }
        SubscribeAll {
            finalized_block_scale_encoded_header: self.tree.finalized().header.encode(&self.params),
            finalized_block_runtime: None,
            non_finalized_blocks_ancestry_order: self
                .tree
                .ancestry_order()
                .skip(1)
                .map(|b| BlockNotification {
                    is_new_best: b.hash == self.tree.best().hash,
                    scale_encoded_header: b.header.encode(&self.params),
                    parent_hash: b.header.parent,
                })
                .collect(),
            new_blocks: rx,
        }
    }

    fn insert(&mut self, header: Header, now: u64) -> Result<(), InsertFailure> {
        if self.stopped || header.encode(&self.params).len() > self.header_bytes {
            return Err(InsertFailure::ResourceLimit);
        }
        let hash = header.hash(&self.params);
        match self.tree.insert(header.parent, header, now) {
            Ok(tree::Insert::AlreadyKnown) => Ok(()),
            Ok(tree::Insert::Inserted { evicted, .. }) => {
                if !evicted.is_empty() {
                    self.subscribers.clear();
                }
                if let Some(block) = self.tree.get(&hash) {
                    let notification = Notification::Block(BlockNotification {
                        is_new_best: self.tree.best().hash == hash,
                        scale_encoded_header: block.header.encode(&self.params),
                        parent_hash: block.header.parent,
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

pub(super) async fn run<P: PlatformRef>(
    platform: P,
    log_name: String,
    config: Config,
    rx: async_channel::Receiver<ToBackground>,
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
            match request {
                ToBackground::SubscribeAll {
                    send_back,
                    buffer_size,
                    runtime_interest,
                } => {
                    let _ =
                        send_back.send(state.lock().await.subscribe(buffer_size, runtime_interest));
                }
                ToBackground::SerializeChainInformation { send_back } => {
                    let _ = send_back.send(None);
                }
                ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                    let _ = send_back.send(false);
                }
                ToBackground::SyncingPeers { send_back } => {
                    let _ = send_back.send(Vec::new());
                }
                ToBackground::PeersAssumedKnowBlock { send_back, .. } => {
                    let _ = send_back.send(Vec::new());
                }
                ToBackground::SubscribeSyncStatus { send_back } => {
                    let (tx, rx) = async_channel::bounded(1);
                    let _ = tx.try_send(SyncStatus::Ready);
                    let _ = send_back.send(rx);
                }
            }
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

async fn peer_loop<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    peer: &Peer,
    peer_index: usize,
    params: &Params,
    state: Arc<async_lock::Mutex<State>>,
) {
    let mut backoff = 1;
    let mut fetch_size = FetchSize::default();
    loop {
        if state.lock().await.stopped {
            future::pending::<()>().await;
        }
        let address = MultiStreamAddress::WebTransport {
            ip: peer.ip,
            port: peer.port,
            cert_hashes: Cow::Owned(
                jam_webtransport_cert::certificate_hashes(
                    &peer.identity,
                    platform.now_from_unix_epoch().as_secs(),
                )
                .to_vec(),
            ),
        };
        if !platform.supports_connection_type((&address).into()) {
            return;
        }
        log!(platform, Debug, log_name, "jam-connect");
        let connected = future::or(
            async { Some(platform.connect_multistream(address).await) },
            async {
                platform.sleep(TIMEOUT).await;
                None
            },
        )
        .await;
        if let Some(connected) = connected {
            let started = platform.now();
            drive(
                platform,
                log_name,
                params,
                peer_index,
                &state,
                connected.connection,
                &mut fetch_size,
            )
            .await;
            let mut s = state.lock().await;
            if s.proof_owner.is_some_and(|(owner, _)| owner == peer_index) {
                s.proof_owner = None;
            }
            drop(s);
            if platform.now() - started >= Duration::from_secs(60) {
                backoff = 1;
            }
        }
        log!(platform, Debug, log_name, "jam-reconnect");
        platform.sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

struct Stream<P: PlatformRef> {
    id: u64,
    stream: Pin<Box<P::Stream>>,
    opened: P::Instant,
    limited_lifetime: bool,
    request: Option<net::RequestId>,
}

/// Retained across reconnects so an oversized response cannot repeat forever.
struct FetchSize {
    count: u32,
    ceiling: u32,
}
impl Default for FetchSize {
    fn default() -> Self {
        Self {
            count: 1,
            ceiling: 64,
        }
    }
}
impl FetchSize {
    fn received(&mut self, bytes: usize) {
        if bytes < FRAME_BYTES / 2 {
            self.count = (self.count * 2).min(self.ceiling);
        }
    }
    fn oversized(&mut self) {
        self.count = (self.count / 2).max(1);
        self.ceiling = self.count;
    }
}

async fn drive<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    params: &Params,
    peer_index: usize,
    state: &Arc<async_lock::Mutex<State>>,
    mut transport: P::MultiStream,
    fetch_size: &mut FetchSize,
) {
    let handshake = {
        let s = state.lock().await;
        Handshake {
            final_: Final {
                hash: s.tree.finalized().hash,
                slot: s.tree.finalized().slot,
            },
            leaves: s.tree.leaves().into_iter().take(8).collect(),
        }
    };
    let Ok(mut connection) = net::Connection::new(
        params.clone(),
        handshake,
        net::Limits {
            max_message_size: FRAME_BYTES,
            max_body_bytes: FRAME_BYTES,
            max_leaves_in_handshake: 8,
            max_pending_requests: 2,
            max_streams: 4,
        },
    ) else {
        return;
    };
    let mut streams: Vec<Stream<P>> = Vec::new();
    let mut opening: Option<(net::SubstreamKind, P::Instant)> = None;
    let mut next_id = 0u64;
    let mut handshaken = false;
    let started = platform.now();
    let mut last_activity = started.clone();
    let mut peer_slot = 0;
    // A fallback cursor can traverse known headers without changing local best.
    let mut cursor = None;
    let mut fallback = false;
    let mut waiting_for_finality = None;
    let mut repair = Vec::new();
    let mut imports = VecDeque::new();
    let mut repair_ready = false;
    let mut announcements = VecDeque::new();
    let mut requested: Option<(net::RequestId, BlockRequest, P::Instant)> = None;
    let mut proof_requested: Option<(net::RequestId, Hash, P::Instant)> = None;
    let mut advertised: Option<Final> = None;
    loop {
        // A turn performs bounded protocol work and at most one ancestry insertion.
        // In particular, never retain the shared tree lock across this yield: RPC
        // consumers and the other peer must be able to run between notifications.
        future::yield_now().await;
        let mut local_progress = false;
        let now = platform.now();
        if (!handshaken && now.clone() - started.clone() >= TIMEOUT)
            || now.clone() - last_activity.clone() >= IDLE_TIMEOUT
        {
            return;
        }
        if let Some((kind, when)) = &opening
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.outgoing_open_failed(*kind);
            return;
        }
        // This deadline starts while the request is still queued, before a stream
        // reservation exists. Peer-created streams cannot starve it indefinitely.
        if let Some((id, _, when)) = &requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            return;
        }
        if let Some((id, _, when)) = &proof_requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            return;
        }
        if streams
            .iter()
            .any(|s| s.limited_lifetime && now.clone() - s.opened.clone() >= TIMEOUT)
        {
            return;
        }
        if opening.is_none()
            && let Some(kind) = connection.desired_outgoing_substreams()
        {
            opening = Some((kind, now.clone()));
            platform.open_out_substream(&mut transport);
        }
        let mut events = Vec::new();
        let mut proof_unavailable = false;
        let mut index = 0;
        while index < streams.len() {
            let stream = &mut streams[index];
            let request = stream.request;
            let mut access = platform.read_write_access(stream.stream.as_mut()).ok();
            if access.is_none() {
                drop(access);
                if let Some((id, _, _)) = &proof_requested
                    && request == Some(*id)
                {
                    let _ = connection.cancel_request(*id, net::RequestError::Rejected);
                    proof_requested = None;
                    proof_unavailable = true;
                    streams.remove(index);
                    local_progress = true;
                    continue;
                }
                if let Some((id, _, _)) = &requested
                    && request == Some(*id)
                {
                    if let Some(event) =
                        connection.substream_reset(stream.id, net::RequestError::Rejected)
                    {
                        events.push(event);
                    }
                    streams.remove(index);
                    local_progress = true;
                    continue;
                }
                return;
            }
            let mut rw = match access.take() {
                Some(rw) => rw,
                None => return,
            };
            drop(access);
            if rw.incoming_buffer.len() > FRAME_BYTES + 4 || rw.write_bytes_queued > 65536 {
                return;
            }
            let mut output = [0; 4096];
            let queueable = rw
                .write_bytes_queueable
                .unwrap_or(0)
                .min(output.len())
                .min(65536usize.saturating_sub(rw.write_bytes_queued));
            let progress = connection.read_write(
                stream.id,
                &rw.incoming_buffer,
                rw.expected_incoming_bytes.is_none(),
                &mut output[..queueable],
            );
            local_progress |= progress.read != 0
                || progress.written != 0
                || progress.finish_write
                || progress.reset
                || progress.event.is_some();
            rw.incoming_buffer.drain(..progress.read);
            rw.read_bytes += progress.read;
            if let Some(expected) = &mut rw.expected_incoming_bytes {
                *expected = 1;
            }
            if progress.written != 0 {
                rw.write_from_vec(&mut output[..progress.written].to_vec());
            }
            if progress.finish_write {
                rw.close_write();
            }
            if progress.read != 0 {
                last_activity = now.clone();
            }
            let retired = progress.reset
                || matches!(
                    &progress.event,
                    Some(
                        net::Event::BlockResponse { .. }
                            | net::Event::JustificationResponse { .. }
                            | net::Event::RequestFailed { .. }
                    )
                );
            drop(rw);
            if let Some(event) = progress.event {
                events.push(event);
            }
            if retired {
                streams.remove(index);
            } else {
                index += 1;
            }
        }
        if proof_unavailable {
            state.lock().await.proof_owner = None;
        }
        for event in events {
            match event {
                net::Event::HandshakeReceived(h) => {
                    handshaken = true;
                    advertised = Some(h.final_.clone());
                    peer_slot = h
                        .leaves
                        .iter()
                        .map(|leaf| leaf.slot)
                        .chain(core::iter::once(h.final_.slot))
                        .max()
                        .unwrap_or(0);
                }
                net::Event::Announcement(a) => {
                    log!(platform, Debug, log_name, "jam-announcement");
                    peer_slot = peer_slot.max(a.header.slot).max(a.final_.slot);
                    if waiting_for_finality.is_some_and(|slot| a.final_.slot > slot) {
                        cursor = Some(state.lock().await.tree.finalized().hash);
                        fallback = true;
                        waiting_for_finality = None;
                    }
                    advertised = Some(a.final_);
                    let s = state.lock().await;
                    if a.header.slot > s.tree.finalized().slot
                        && a.header.encode(params).len() <= s.header_bytes
                        && announcements.len() < REPAIR_LIMIT
                        && !announcements.contains(&a.header)
                    {
                        announcements.push_back(a.header);
                    }
                }
                net::Event::BlockResponse { request_id, blocks } => {
                    let Some((id, request, _)) = requested.take() else {
                        return;
                    };
                    if id != request_id {
                        return;
                    }
                    let mut bytes = 0;
                    for block in blocks {
                        let header_len = block.header.encode(params).len();
                        if header_len > state.lock().await.header_bytes {
                            return;
                        }
                        bytes += header_len + block.body.len();
                        drop(block.body);
                        if request.direction == Direction::DescendingInclusive {
                            let parent = block.header.parent;
                            repair.push(block.header);
                            repair_ready = state.lock().await.tree.get(&parent).is_some();
                            if !repair_ready && repair.len() >= REPAIR_LIMIT {
                                repair.clear();
                            }
                        } else {
                            imports.push_back(block.header);
                        }
                    }
                    if request.direction == Direction::AscendingExclusive {
                        fetch_size.received(bytes);
                    }
                }
                net::Event::JustificationResponse {
                    request_id,
                    target,
                    justification,
                } => {
                    let Some((id, expected, _)) = proof_requested.take() else {
                        return;
                    };
                    if id != request_id || target != expected {
                        return;
                    }
                    let mut s = state.lock().await;
                    s.proof_owner = None;
                    if let Err(error) = s.finalize(target, &justification) {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-finality-rejected",
                            error = alloc::format!("{error:?}")
                        );
                        return;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-finalized",
                        slot = s.tree.finalized().slot,
                        set_id = s.authorities.set_id(),
                        retained = s.tree.len()
                    );
                }
                net::Event::RequestFailed { request_id, .. }
                    if proof_requested
                        .as_ref()
                        .is_some_and(|(id, _, _)| *id == request_id) =>
                {
                    proof_requested = None;
                    state.lock().await.proof_owner = None;
                }
                net::Event::RequestFailed { request_id, .. } => {
                    let Some((id, request, _)) = requested.take() else {
                        return;
                    };
                    if id != request_id {
                        return;
                    }
                    if request.direction == Direction::DescendingInclusive {
                        repair.clear();
                        repair_ready = false;
                    } else if !fallback {
                        cursor = Some(state.lock().await.tree.finalized().hash);
                        fallback = true;
                    } else if request.hash == state.lock().await.tree.finalized().hash {
                        // This peer cannot extend our authenticated root.
                        return;
                    } else {
                        // First-child selection can repeat a dead branch. Wait for
                        // an announcement repair or for the server to prune it.
                        waiting_for_finality = Some(advertised.as_ref().map_or(0, |f| f.slot));
                    }
                }
                net::Event::ProtocolError(net::ProtocolError::MessageTooLarge) => {
                    if requested.as_ref().is_some_and(|(_, request, _)| {
                        request.direction == Direction::AscendingExclusive
                    }) {
                        fetch_size.oversized();
                    }
                    return;
                }
                net::Event::ProtocolError(_) => return,
            }
        }
        let pause_imports = {
            let s = state.lock().await;
            if s.tree.len() >= s.max_blocks && s.proof_owner.is_none() {
                return;
            }
            s.proof_owner.is_some() && s.tree.len() + 1 >= s.max_blocks
        };
        if !pause_imports && !imports.is_empty() {
            if let Some(header) = imports.pop_front() {
                let hash = header.hash(params);
                let mut s = state.lock().await;
                // Another peer may have finalized this prefix while the batch
                // was in flight. Its pruned ancestors need no re-import.
                let result = if header.slot <= s.tree.finalized().slot {
                    Ok(())
                } else {
                    s.insert(header, platform.now_from_unix_epoch().as_secs())
                };
                match result {
                    Ok(()) => {
                        cursor = fallback.then_some(hash);
                        last_activity = now.clone();
                        log!(platform, Debug, log_name, "jam-header-inserted");
                    }
                    Err(InsertFailure::Tree(tree::InsertError::Verify(_))) if !fallback => {
                        imports.clear();
                        cursor = Some(s.tree.finalized().hash);
                        fallback = true;
                    }
                    Err(_) => return,
                }
                local_progress = true;
            }
        } else if !pause_imports && requested.is_none() {
            let header = if repair_ready {
                repair.pop()
            } else if repair.is_empty() {
                announcements.pop_front()
            } else {
                None
            };
            if let Some(header) = header {
                let mut s = state.lock().await;
                if header.slot > s.tree.finalized().slot {
                    match s.insert(header.clone(), platform.now_from_unix_epoch().as_secs()) {
                        Ok(()) => {
                            cursor = None;
                            fallback = false;
                            waiting_for_finality = None;
                            last_activity = now.clone();
                        }
                        Err(InsertFailure::Tree(tree::InsertError::UnknownParent)) => {
                            // Finality from another peer may have pruned the
                            // parent since the repair was marked ready.
                            repair_ready = false;
                            repair.push(header);
                            if repair.len() >= REPAIR_LIMIT {
                                repair.clear();
                            }
                        }
                        Err(_) => return,
                    }
                }
                repair_ready = !repair.is_empty() && repair_ready;
                local_progress = true;
            }
        }
        if handshaken
            && proof_requested.is_none()
            && let Some(advertised) = &advertised
        {
            let mut s = state.lock().await;
            if let Some(target) = s.reserve_proof(peer_index, advertised) {
                let Ok(id) = connection.request_justification(target) else {
                    return;
                };
                proof_requested = Some((id, target, platform.now()));
                local_progress = true;
            }
        }
        if handshaken && requested.is_none() && !repair_ready && imports.is_empty() {
            let s = state.lock().await;
            if s.tree.len() + 1 >= s.max_blocks && s.proof_owner.is_some() {
                // The proof already in flight must get a turn before more imports.
            } else if s.tree.len() >= s.max_blocks && s.proof_owner.is_none() {
                // All proof candidates failed: don't deadlock on an unfinalizable fork.
                return;
            } else {
                let request = if let Some(header) = repair.last() {
                    Some(BlockRequest {
                        hash: header.parent,
                        direction: Direction::DescendingInclusive,
                        max_blocks: 1,
                    })
                } else if waiting_for_finality.is_none() {
                    let head = cursor
                        .and_then(|hash| s.tree.get(&hash))
                        .unwrap_or_else(|| s.tree.best());
                    (peer_slot > head.slot).then_some(BlockRequest {
                        hash: head.hash,
                        direction: Direction::AscendingExclusive,
                        max_blocks: fetch_size.count,
                    })
                } else {
                    None
                };
                if let Some(request) = request {
                    let Ok(id) = connection.request_blocks(request.clone()) else {
                        return;
                    };
                    requested = Some((id, request, platform.now()));
                    local_progress = true;
                    log!(platform, Debug, log_name, "jam-block-request-queued");
                }
            }
        }
        // Wake for substreams, transport buffer progress, or bounded protocol deadlines.
        let next = future::or(
            async { Some(platform.next_substream(&mut transport).await) },
            async {
                // B2 can leave buffered input after an event, or need another call
                // after committing FIN. No new platform edge is promised for that
                // work. Poll substreams above, then cooperatively drive again.
                if local_progress
                    || ((repair_ready || !imports.is_empty()) && !pause_imports)
                    || (!pause_imports && requested.is_none() && !announcements.is_empty())
                {
                    return None;
                }
                future::or(
                    async {
                        let mut waits = futures_util::stream::FuturesUnordered::new();
                        for stream in &mut streams {
                            waits.push(platform.wait_read_write_again(stream.stream.as_mut()));
                        }
                        if waits.next().await.is_none() {
                            future::pending::<()>().await;
                        }
                    },
                    platform.sleep(Duration::from_millis(100)),
                )
                .await;
                None
            },
        )
        .await;
        match next {
            Some(Some((stream, direction))) => {
                let Some(id) = next_id.checked_add(1) else {
                    return;
                };
                next_id = id;
                let mut request = None;
                let limited_lifetime = match direction {
                    SubstreamDirection::Outbound => {
                        let Some((kind, _)) = opening.take() else {
                            return;
                        };
                        request = match kind {
                            net::SubstreamKind::Ce128 { request_id }
                            | net::SubstreamKind::Ce130 { request_id } => Some(request_id),
                            _ => None,
                        };
                        if connection.substream_opened(id, kind).is_err() {
                            let _ = connection.outgoing_open_failed(kind);
                            return;
                        }
                        matches!(
                            kind,
                            net::SubstreamKind::Ce128 { .. } | net::SubstreamKind::Ce130 { .. }
                        )
                    }
                    SubstreamDirection::Inbound => {
                        if connection.substream_incoming(id).is_err() {
                            continue;
                        }
                        true
                    }
                };
                streams.push(Stream {
                    id,
                    stream: Box::pin(stream),
                    opened: platform.now(),
                    limited_lifetime,
                    request,
                });
            }
            Some(None) => return,
            None => {}
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
