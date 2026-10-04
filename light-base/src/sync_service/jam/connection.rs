// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! One connection slot: the loop that takes candidates from the pool, dialing
//! one, and driving the connection's streams, requests and deadlines until it
//! ends.

use super::{
    FRAME_BYTES, IDLE_TIMEOUT, POOL_POLL, PREEMPT_POLL, State, TIMEOUT, WARP_BYTES,
    discovery::{Peer, Release, Source},
    log::{End, Opt, Tag, Token, elapsed_ms, event, request_ended},
    warp::{Warp, warp_step},
};
use crate::{
    jam_webtransport_cert, log,
    platform::{MultiStreamAddress, PlatformRef, SubstreamDirection},
};
use alloc::{borrow::Cow, boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::{pin::Pin, time::Duration};
use futures_lite::{StreamExt as _, future};
use smoldot::jam::{
    net,
    params::Params,
    types::{BlockRequest, Final, Handshake, Hash, Header},
};

/// One connection slot. It keeps `slot` as its `peer_index` for life and asks
/// the pool for a candidate whenever it has none: on a failed connect or an
/// ended connection it releases the candidate (recording the failure against
/// that candidate) and asks again, so backoff is per candidate, not per slot.
pub(super) async fn slot_loop<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    slot: usize,
    params: &Params,
    state: Arc<async_lock::Mutex<State>>,
    origin: P::Instant,
    mut current: Option<Peer>,
) {
    let mut fetch_size = FetchSize::default();
    let mut root_probe = None;
    let mut previous: Option<jam_webtransport_cert::P256PeerId> = None;
    // Log a wait once when it starts, not once per poll.
    let mut waiting = false;
    loop {
        if state.lock().await.stopped {
            future::pending::<()>().await;
        }
        let peer = match current.take() {
            Some(peer) => peer,
            None => {
                let now = platform.now() - origin.clone();
                // Bind first: a guard in the scrutinee would be held while sleeping.
                let acquired = state.lock().await.acquire_candidate(slot, now);
                match acquired {
                    Ok(peer) => peer,
                    Err(wait) => {
                        if !waiting {
                            waiting = true;
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-pool-waiting",
                                slot = slot,
                                ready_in_ms = Opt(wait.map(|wait| wait.as_millis()))
                            );
                        }
                        let wait = wait.map_or(POOL_POLL, |wait| wait.min(POOL_POLL));
                        platform.sleep(wait.max(Duration::from_millis(1))).await;
                        continue;
                    }
                }
            }
        };
        waiting = false;
        log!(
            platform,
            Debug,
            log_name,
            "jam-slot-assigned",
            slot = slot,
            source = peer.source.as_str(),
            address = peer.address(),
            p256 = peer.identity.to_text()
        );
        if previous != Some(peer.identity) {
            // The root probe describes one peer's answers, not the slot's.
            root_probe = None;
            previous = Some(peer.identity);
        }
        let outcome = connect_once(
            platform,
            log_name,
            &peer,
            slot,
            params,
            &state,
            (&mut fetch_size, &mut root_probe),
            Some(origin.clone()),
        )
        .await;
        let now = platform.now() - origin.clone();
        match outcome {
            None => {
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-slot-unsupported",
                    slot = slot,
                    address = peer.address()
                );
                state
                    .lock()
                    .await
                    .discovery
                    .pool
                    .release(slot, Release::Unsupported, now);
                continue;
            }
            Some(Outcome { stopped: true, .. }) => continue,
            Some(Outcome {
                preempted: Some(next),
                ..
            }) => {
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-slot-preempted",
                    slot = slot,
                    from = peer.address(),
                    to = next.address()
                );
                current = Some(next);
            }
            Some(Outcome { lasted, .. }) => {
                state
                    .lock()
                    .await
                    .discovery
                    .pool
                    .release(slot, Release::Ended { lasted }, now);
            }
        }
        log!(platform, Debug, log_name, "jam-reconnect");
    }
}

/// How one connection attempt ended.
pub(super) struct Outcome {
    /// Zero when the transport never connected.
    pub(super) lasted: Duration,
    /// The driver stopped the chain; the slot parks.
    pub(super) stopped: bool,
    /// The pool moved this slot to this bootnode while connected.
    pub(super) preempted: Option<Peer>,
}

/// Dial `peer` once on slot `peer_index` and drive the connection until it
/// ends, then release the proof, warp and read ownership it may hold.
/// `None` when the platform cannot dial this address type. With `preempt`
/// (the pool's time origin), a slot on a discovered peer may be moved to a
/// bootnode whose retry interval has passed.
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_once<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    peer: &Peer,
    peer_index: usize,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
    (fetch_size, root_probe): (&mut FetchSize, &mut Option<Hash>),
    preempt: Option<P::Instant>,
) -> Option<Outcome> {
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
        return None;
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
    let mut outcome = Outcome {
        lasted: Duration::ZERO,
        stopped: false,
        preempted: None,
    };
    let Some(connected) = connected else {
        log!(
            platform,
            Debug,
            log_name,
            "jam-peer-disconnected",
            slot = peer_index,
            source = peer.source.as_str(),
            address = peer.address(),
            lasted_ms = 0,
            reason = End::ConnectTimeout.as_str()
        );
        return Some(outcome);
    };
    let started = platform.now();
    let driving = async {
        Err(drive_connection(
            platform,
            log_name,
            params,
            peer_index,
            state,
            connected.connection,
            (fetch_size, root_probe),
        )
        .await)
    };
    let ended: Result<Peer, End> = match preempt {
        Some(origin) if peer.source != Source::Bootnode => {
            future::or(driving, async {
                loop {
                    platform.sleep(PREEMPT_POLL).await;
                    let now = platform.now() - origin.clone();
                    if let Some(next) = state.lock().await.preempt_candidate(peer_index, now) {
                        return Ok(next);
                    }
                }
            })
            .await
        }
        _ => driving.await,
    };
    let reason = match &ended {
        Ok(_) => End::Preempted,
        Err(end) => *end,
    };
    outcome.preempted = ended.ok();
    outcome.lasted = platform.now() - started;
    let mut s = state.lock().await;
    s.reads.release(peer_index, false);
    if s.proof_owner.is_some_and(|(owner, _)| owner == peer_index) {
        s.proof_owner = None;
    }
    if s.warp_owner == Some(peer_index) {
        s.warp_owner = None;
    }
    outcome.stopped = s.stopped;
    drop(s);
    log!(
        platform,
        Debug,
        log_name,
        "jam-peer-disconnected",
        slot = peer_index,
        source = peer.source.as_str(),
        address = peer.address(),
        lasted_ms = outcome.lasted.as_millis(),
        reason = reason.as_str()
    );
    Some(outcome)
}

pub(super) struct Stream<P: PlatformRef> {
    id: u64,
    stream: Pin<Box<P::Stream>>,
    opened: P::Instant,
    limited_lifetime: bool,
    request: Option<net::RequestId>,
}

/// Retained across reconnects so an oversized response cannot repeat forever.
pub(super) struct FetchSize {
    pub(super) count: u32,
    pub(super) ceiling: u32,
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
    pub(super) fn received(&mut self, bytes: usize) {
        if bytes < FRAME_BYTES / 2 {
            self.count = (self.count * 2).min(self.ceiling);
        }
    }
    pub(super) fn oversized(&mut self) {
        self.count = (self.count / 2).max(1);
        self.ceiling = self.count;
    }
}

/// The request error of a stream reset, from the peer's application error
/// code if the platform reported one.
pub(super) fn classify_reset(code: Option<u32>) -> net::RequestError {
    match code {
        Some(6) => net::RequestError::NoData,
        Some(2..=5) => net::RequestError::Transient,
        Some(_) => net::RequestError::Rejected,
        None => net::RequestError::ResetWithoutCode,
    }
}

/// Resets without a code in a row, with no response in between, that end a
/// connection. Such a reset is taken as `NoData` where that is a normal
/// answer, so this bounds a peer that fails every request that way.
const RESETS_WITHOUT_CODE: u8 = 3;

/// A request in flight on one connection.
pub(super) struct InFlight<I, T> {
    pub(super) id: net::RequestId,
    /// What the response must match.
    pub(super) expected: T,
    pub(super) queued: I,
    pub(super) tag: Tag,
}

impl<I: Clone + core::ops::Sub<Output = Duration>, T> InFlight<I, T> {
    pub(super) fn new(id: net::RequestId, expected: T, queued: I, tag: Tag) -> Self {
        Self {
            id,
            expected,
            queued,
            tag,
        }
    }

    /// `request` if it is the request `id`.
    fn holding(request: &Option<Self>, id: Option<net::RequestId>) -> Option<&Self> {
        request.as_ref().filter(|r| Some(r.id) == id)
    }

    pub(super) fn holds(request: &Option<Self>, id: Option<net::RequestId>) -> bool {
        Self::holding(request, id).is_some()
    }

    /// The id of `request` once it has been queued for [`TIMEOUT`].
    fn timed_out(request: &Option<Self>, now: &I) -> Option<net::RequestId> {
        request
            .as_ref()
            .filter(|r| now.clone() - r.queued.clone() >= TIMEOUT)
            .map(|r| r.id)
    }
}

/// One connection's state, shared by the steps of [`drive_connection`] in
/// this module and its siblings.
pub(super) struct Conn<'a, P: PlatformRef> {
    pub(super) platform: &'a P,
    pub(super) log_name: &'a str,
    pub(super) params: &'a Params,
    pub(super) peer_index: usize,
    pub(super) state: &'a Arc<async_lock::Mutex<State>>,
    transport: P::MultiStream,
    pub(super) fetch_size: &'a mut FetchSize,
    pub(super) root_probe: &'a mut Option<Hash>,
    pub(super) connection: net::Connection,
    streams: Vec<Stream<P>>,
    opening: Option<(net::SubstreamKind, P::Instant)>,
    next_id: u64,
    pub(super) handshaken: bool,
    pub(super) started: P::Instant,
    pub(super) last_activity: P::Instant,
    pub(super) peer_slot: u32,
    /// A fallback cursor can traverse known headers without changing local best.
    pub(super) cursor: Option<Hash>,
    // The root probe is retained by slot_loop across transient failures. The
    // remaining cursors and repair buffers belong to this connection only.
    pub(super) fallback: bool,
    pub(super) waiting_for_finality: Option<u32>,
    pub(super) repair: Vec<Header>,
    pub(super) imports: VecDeque<Header>,
    pub(super) repair_ready: bool,
    pub(super) announcements: VecDeque<Header>,
    pub(super) requested: Option<InFlight<P::Instant, BlockRequest>>,
    pub(super) proof_requested: Option<InFlight<P::Instant, Hash>>,
    pub(super) state_requested: Option<InFlight<P::Instant, ()>>,
    pub(super) advertised: Option<Final>,
    pub(super) advertisement_revision: u64,
    pub(super) warped: bool,
    pub(super) warp: Option<Warp>,
    pub(super) warp_requested: Option<InFlight<P::Instant, u32>>,
    pub(super) warp_revision: u64,
    /// Resets without a code since the last response.
    resets_without_code: u8,
    /// This turn did work that may leave more to do without a new I/O event.
    pub(super) local_progress: bool,
}

/// Drives one connection until it ends and says why.
pub(super) async fn drive_connection<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    params: &Params,
    peer_index: usize,
    state: &Arc<async_lock::Mutex<State>>,
    transport: P::MultiStream,
    (fetch_size, root_probe): (&mut FetchSize, &mut Option<Hash>),
) -> End {
    let handshake = {
        let s = state.lock().await;
        Handshake {
            final_: Final {
                hash: s.tree.finalized().hash(),
                slot: s.tree.finalized().slot(),
            },
            leaves: s.tree.leaves().into_iter().take(8).collect(),
        }
    };
    if root_probe.is_some_and(|hash| hash != handshake.final_.hash) {
        *root_probe = None;
    }
    let Ok(connection) = net::Connection::new(
        params.clone(),
        handshake,
        net::Limits {
            max_message_size: FRAME_BYTES,
            max_warp_message_size: WARP_BYTES,
            max_body_bytes: FRAME_BYTES,
            max_leaves_in_handshake: 8,
            max_pending_requests: 2,
            max_streams: 4,
        },
    ) else {
        return End::Setup;
    };
    let started = platform.now();
    let mut conn = Conn {
        platform,
        log_name,
        params,
        peer_index,
        state,
        transport,
        fetch_size,
        root_probe,
        connection,
        streams: Vec::new(),
        opening: None,
        next_id: 0,
        handshaken: false,
        last_activity: started.clone(),
        started,
        peer_slot: 0,
        cursor: None,
        fallback: false,
        waiting_for_finality: None,
        repair: Vec::new(),
        imports: VecDeque::new(),
        repair_ready: false,
        announcements: VecDeque::new(),
        requested: None,
        proof_requested: None,
        state_requested: None,
        advertised: None,
        advertisement_revision: 0,
        warped: false,
        warp: None,
        warp_requested: None,
        warp_revision: state.lock().await.warp_revision,
        resets_without_code: 0,
        local_progress: false,
    };
    let end = loop {
        if let Err(end) = conn.turn().await {
            break end;
        }
    };
    conn.cut_short(end);
    end
}

impl<P: PlatformRef> Conn<'_, P> {
    /// One turn of the connection: deadlines, stream I/O and events, then at
    /// most one ancestry insertion and the next requests, then a wait.
    async fn turn(&mut self) -> Result<(), End> {
        // A turn performs bounded protocol work and at most one ancestry insertion.
        // In particular, never retain the shared tree lock across this yield: RPC
        // consumers and the other peer must be able to run between notifications.
        future::yield_now().await;
        {
            let s = self.state.lock().await;
            if s.stopped {
                return Err(End::Stopped);
            }
            if s.warp_revision != self.warp_revision {
                return Err(End::WarpRevision);
            }
        }
        self.local_progress = false;
        let now = self.platform.now();
        self.check_deadlines(&now).await?;
        if self.opening.is_none()
            && let Some(kind) = self.connection.desired_outgoing_substreams()
        {
            self.opening = Some((kind, now.clone()));
            self.platform.open_out_substream(&mut self.transport);
        }
        for event in self.read_write(&now).await? {
            self.handle(event).await?;
        }
        // Checked after the events, so that a reset whose handling ends the
        // connection anyway keeps that reason.
        if self.resets_without_code >= RESETS_WITHOUT_CODE {
            return Err(End::ResetsWithoutCode);
        }
        if self.handshaken && !self.warped {
            self.warp_turn(&now).await?;
        }
        let normal_sync = self.warped && self.state.lock().await.warp_owner.is_none();
        let pause_imports = {
            let s = self.state.lock().await;
            if normal_sync && s.tree.len() >= s.max_blocks && s.proof_owner.is_none() {
                return Err(End::TreeFull);
            }
            !normal_sync || (s.proof_owner.is_some() && s.tree.len() + 1 >= s.max_blocks)
        };
        if !pause_imports && !self.imports.is_empty() {
            self.import_next(&now).await?;
        } else if !pause_imports && self.requested.is_none() {
            self.import_repaired(&now).await?;
        }
        if normal_sync {
            self.discovery_step().await;
        }
        if self.handshaken
            && normal_sync
            && self.proof_requested.is_none()
            && self.state_requested.is_none()
        {
            self.request_justification().await?;
        }
        // Finality and state reads arbitrate the second slot; never enqueue a
        // third request into the connection's two-request budget.
        if self.handshaken
            && self.state_requested.is_none()
            && self.proof_requested.is_none()
            && self.warp_requested.is_none()
        {
            self.request_state().await?;
        }
        if self.handshaken
            && normal_sync
            && self.requested.is_none()
            && !self.repair_ready
            && self.imports.is_empty()
        {
            self.request_blocks().await?;
        }
        self.wait(pause_imports).await
    }

    /// Ends the connection once one of its deadlines has passed.
    async fn check_deadlines(&mut self, now: &P::Instant) -> Result<(), End> {
        if !self.handshaken && now.clone() - self.started.clone() >= TIMEOUT {
            return Err(End::HandshakeTimeout);
        }
        if now.clone() - self.last_activity.clone() >= IDLE_TIMEOUT {
            return Err(End::Idle);
        }
        if let Some((kind, when)) = &self.opening
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = self.connection.outgoing_open_failed(*kind);
            return Err(End::StreamOpenTimeout);
        }
        // This deadline starts while the request is still queued, before a stream
        // reservation exists. Peer-created streams cannot starve it indefinitely.
        let timed_out = [
            (
                InFlight::timed_out(&self.state_requested, now),
                End::StateTimeout,
            ),
            (InFlight::timed_out(&self.requested, now), End::BlockTimeout),
            (
                InFlight::timed_out(&self.proof_requested, now),
                End::JustificationTimeout,
            ),
            (
                InFlight::timed_out(&self.warp_requested, now),
                End::WarpTimeout,
            ),
        ];
        if let Some((id, end)) = timed_out.into_iter().find_map(|(id, end)| Some((id?, end))) {
            let _ = self
                .connection
                .cancel_request(id, net::RequestError::Timeout);
            if end == End::StateTimeout {
                self.state
                    .lock()
                    .await
                    .reads
                    .release(self.peer_index, false);
            }
            return Err(end);
        }
        if self
            .streams
            .iter()
            .any(|s| s.limited_lifetime && now.clone() - s.opened.clone() >= TIMEOUT)
        {
            return Err(End::StreamTimeout);
        }
        Ok(())
    }

    /// Reads and writes each stream once and returns the connection's events.
    async fn read_write(&mut self, now: &P::Instant) -> Result<Vec<net::Event>, End> {
        let mut events = Vec::new();
        let mut proof_unavailable = false;
        let mut index = 0;
        while index < self.streams.len() {
            let stream = &mut self.streams[index];
            let request = stream.request;
            let (mut access, error) = match self.platform.read_write_access(stream.stream.as_mut())
            {
                Ok(access) => (Some(access), None),
                Err(error) => (
                    None,
                    Some((
                        alloc::format!("{error}"),
                        self.platform.stream_reset_code(&error),
                    )),
                ),
            };
            if let Some((message, code)) = error {
                let reason = classify_reset(code);
                // Which of this connection's requests the stream carried.
                let owner = [
                    (
                        "state",
                        InFlight::holding(&self.state_requested, request).map(|r| r.tag),
                    ),
                    (
                        "block",
                        InFlight::holding(&self.requested, request).map(|r| r.tag),
                    ),
                    (
                        "justification",
                        InFlight::holding(&self.proof_requested, request).map(|r| r.tag),
                    ),
                    (
                        "warp",
                        InFlight::holding(&self.warp_requested, request).map(|r| r.tag),
                    ),
                ]
                .into_iter()
                .find_map(|(kind, tag)| Some((kind, tag?.req)));
                event!(
                    self,
                    "jam-stream-reset",
                    slot = self.peer_index,
                    stream = owner.map_or("other", |(kind, _)| kind),
                    req = Opt(owner.map(|(_, req)| req)),
                    reason = ?reason,
                    message = message
                );
                drop(access);
                if reason == net::RequestError::ResetWithoutCode {
                    self.resets_without_code += 1;
                }
                if InFlight::holds(&self.state_requested, request)
                    || InFlight::holds(&self.requested, request)
                    || InFlight::holds(&self.warp_requested, request)
                {
                    if let Some(event) = self.connection.substream_reset(stream.id, reason) {
                        events.push(event);
                    }
                    self.streams.remove(index);
                    self.local_progress = true;
                    continue;
                }
                if let Some(r) = InFlight::holding(&self.proof_requested, request) {
                    if self.warp.is_some() {
                        return Err(End::StreamReset);
                    }
                    let _ = self.connection.cancel_request(r.id, reason);
                    request_ended!(
                        self,
                        "jam-justification-request-ended",
                        r,
                        "failed",
                        error = ?reason
                    );
                    self.proof_requested = None;
                    proof_unavailable = true;
                    self.streams.remove(index);
                    self.local_progress = true;
                    continue;
                }
                return Err(End::StreamReset);
            }
            let mut rw = match access.take() {
                Some(rw) => rw,
                None => return Err(End::Transport),
            };
            drop(access);
            let incoming_limit = if InFlight::holds(&self.state_requested, request) {
                FRAME_BYTES + 496 * 64 + 8
            } else if InFlight::holds(&self.warp_requested, request) {
                WARP_BYTES + 4
            } else {
                FRAME_BYTES + 4
            };
            if rw.incoming_buffer.len() > incoming_limit || rw.write_bytes_queued > 65536 {
                return Err(End::Limit);
            }
            let mut output = [0; 4096];
            let queueable = rw
                .write_bytes_queueable
                .unwrap_or(0)
                .min(output.len())
                .min(65536usize.saturating_sub(rw.write_bytes_queued));
            let progress = self.connection.read_write(
                stream.id,
                &rw.incoming_buffer,
                rw.expected_incoming_bytes.is_none(),
                &mut output[..queueable],
            );
            self.local_progress |= progress.read != 0
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
                self.last_activity = now.clone();
            }
            let response = matches!(
                &progress.event,
                Some(
                    net::Event::BlockResponse { .. }
                        | net::Event::StateResponse { .. }
                        | net::Event::JustificationResponse { .. }
                        | net::Event::WarpResponse { .. }
                )
            );
            if response {
                self.resets_without_code = 0;
            }
            let retired = progress.reset
                || response
                || matches!(&progress.event, Some(net::Event::RequestFailed { .. }));
            drop(rw);
            if let Some(event) = progress.event {
                events.push(event);
            }
            if retired {
                self.streams.remove(index);
            } else {
                index += 1;
            }
        }
        if proof_unavailable {
            self.state.lock().await.proof_owner = None;
        }
        Ok(events)
    }

    /// Handles one event of the connection.
    async fn handle(&mut self, event: net::Event) -> Result<(), End> {
        match event {
            net::Event::StateResponse {
                request_id,
                response,
            } => self.state_response(request_id, response).await,
            net::Event::RequestFailed { request_id, reason }
                if InFlight::holds(&self.state_requested, Some(request_id)) =>
            {
                self.state_failed(reason).await
            }
            net::Event::HandshakeReceived(h) => {
                self.handshake(h).await;
                Ok(())
            }
            net::Event::Announcement(a) => self.announcement(a).await,
            net::Event::BlockResponse { request_id, blocks } => {
                self.block_response(request_id, blocks).await
            }
            net::Event::WarpResponse {
                request_id,
                start_set_id,
                fragments,
            } => {
                self.warp_response(request_id, start_set_id, fragments)
                    .await
            }
            net::Event::JustificationResponse {
                request_id,
                target,
                justification,
            } => {
                self.justification_response(request_id, target, justification)
                    .await
            }
            net::Event::RequestFailed { request_id, reason }
                if InFlight::holds(&self.proof_requested, Some(request_id)) =>
            {
                self.justification_failed(reason).await
            }
            net::Event::RequestFailed { request_id, reason }
                if InFlight::holds(&self.warp_requested, Some(request_id)) =>
            {
                self.warp_failed(reason)
            }
            net::Event::RequestFailed { request_id, reason } => {
                self.block_failed(request_id, reason).await
            }
            net::Event::ProtocolError(net::ProtocolError::MessageTooLarge) => {
                self.message_too_large()
            }
            net::Event::ProtocolError(error) => {
                event!(
                    self,
                    "jam-peer-protocol-error",
                    slot = self.peer_index,
                    error = Token(&error)
                );
                Err(End::ProtocolError)
            }
        }
    }

    /// Waits for a substream, transport buffer progress, or a bounded protocol
    /// deadline, and takes a substream the transport opened.
    async fn wait(&mut self, pause_imports: bool) -> Result<(), End> {
        let platform = self.platform;
        let Self {
            transport,
            streams,
            local_progress,
            repair_ready,
            imports,
            requested,
            announcements,
            ..
        } = self;
        // Wake for substreams, transport buffer progress, or bounded protocol deadlines.
        let next = future::or(
            async { Some(platform.next_substream(transport).await) },
            async {
                // The connection can leave buffered input after an event, or need
                // another call after committing FIN. No new platform edge is promised
                // for that work. Poll substreams above, then cooperatively drive again.
                if *local_progress
                    || ((*repair_ready || !imports.is_empty()) && !pause_imports)
                    || (!pause_imports && requested.is_none() && !announcements.is_empty())
                {
                    return None;
                }
                future::or(
                    async {
                        let mut waits = futures_util::stream::FuturesUnordered::new();
                        for stream in streams.iter_mut() {
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
            Some(Some((stream, direction))) => self.accept(stream, direction),
            Some(None) => Err(End::Transport),
            None => Ok(()),
        }
    }

    /// Registers a substream the transport opened.
    fn accept(&mut self, stream: P::Stream, direction: SubstreamDirection) -> Result<(), End> {
        let Some(id) = self.next_id.checked_add(1) else {
            return Err(End::Limit);
        };
        self.next_id = id;
        let mut request = None;
        let limited_lifetime = match direction {
            SubstreamDirection::Outbound => {
                let Some((kind, _)) = self.opening.take() else {
                    return Err(End::ProtocolError);
                };
                request = match kind {
                    net::SubstreamKind::Ce128 { request_id }
                    | net::SubstreamKind::Ce129 { request_id }
                    | net::SubstreamKind::Ce130 { request_id }
                    | net::SubstreamKind::Ce153 { request_id } => Some(request_id),
                    _ => None,
                };
                if self.connection.substream_opened(id, kind).is_err() {
                    let _ = self.connection.outgoing_open_failed(kind);
                    return Err(End::ProtocolError);
                }
                matches!(
                    kind,
                    net::SubstreamKind::Ce128 { .. }
                        | net::SubstreamKind::Ce129 { .. }
                        | net::SubstreamKind::Ce130 { .. }
                        | net::SubstreamKind::Ce153 { .. }
                )
            }
            SubstreamDirection::Inbound => {
                if self.connection.substream_incoming(id).is_err() {
                    return Ok(());
                }
                true
            }
        };
        self.streams.push(Stream {
            id,
            stream: Box::pin(stream),
            opened: self.platform.now(),
            limited_lifetime,
            request,
        });
        Ok(())
    }

    /// Logs how the requests still in flight ended with the connection, once
    /// each, and where an unfinished warp join stood.
    fn cut_short(self, end: End) {
        // Requests still in flight end with the connection: say how, once each.
        let outcome = |timeout: End| {
            if end == timeout {
                "timeout"
            } else {
                "cancelled"
            }
        };
        let pending = [
            self.requested.map(|r| {
                (
                    "jam-block-request-ended",
                    r.tag,
                    r.queued,
                    End::BlockTimeout,
                )
            }),
            self.proof_requested.map(|r| {
                (
                    "jam-justification-request-ended",
                    r.tag,
                    r.queued,
                    End::JustificationTimeout,
                )
            }),
            self.state_requested.map(|r| {
                (
                    "jam-state-request-ended",
                    r.tag,
                    r.queued,
                    End::StateTimeout,
                )
            }),
            self.warp_requested
                .map(|r| ("jam-warp-request-ended", r.tag, r.queued, End::WarpTimeout)),
        ];
        for (name, tag, queued, timeout) in pending.into_iter().flatten() {
            event!(
                self,
                name,
                slot = self.peer_index,
                req = tag.req,
                purpose = tag.purpose,
                outcome = outcome(timeout),
                reason = end.as_str(),
                elapsed_ms = elapsed_ms(self.platform, &queued)
            );
        }
        // A rejection already said where the join failed.
        if let Some(w) = &self.warp
            && !matches!(end, End::WarpRejected | End::WarpFailed)
        {
            event!(
                self,
                "jam-warp-abandoned",
                slot = self.peer_index,
                step = warp_step(w),
                fragments = w.fragments,
                reason = end.as_str()
            );
        }
    }
}
