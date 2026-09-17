// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! One connection: dialing a peer again and again with backoff, and driving
//! each connection's streams, requests and deadlines until it ends.

use super::{
    FRAME_BYTES, IDLE_TIMEOUT, Peer, State, TIMEOUT,
    log::{End, Tag, Token, elapsed_ms, event},
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

pub(super) async fn peer_loop<P: PlatformRef>(
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
            drive_connection(
                platform,
                log_name,
                params,
                peer_index,
                &state,
                connected.connection,
                &mut fetch_size,
            )
            .await;
            if platform.now() - started >= Duration::from_secs(60) {
                backoff = 1;
            }
        }
        log!(platform, Debug, log_name, "jam-reconnect");
        platform.sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
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

    pub(super) fn holds(request: &Option<Self>, id: Option<net::RequestId>) -> bool {
        request.as_ref().is_some_and(|r| Some(r.id) == id)
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
    pub(super) fallback: bool,
    pub(super) waiting_for_finality: Option<u32>,
    pub(super) repair: Vec<Header>,
    pub(super) imports: VecDeque<Header>,
    pub(super) repair_ready: bool,
    pub(super) announcements: VecDeque<Header>,
    pub(super) requested: Option<InFlight<P::Instant, BlockRequest>>,
    pub(super) advertised: Option<Final>,
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
    fetch_size: &mut FetchSize,
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
    let Ok(connection) = net::Connection::new(
        params.clone(),
        handshake,
        net::Limits {
            max_message_size: FRAME_BYTES,
            max_body_bytes: FRAME_BYTES,
            max_leaves_in_handshake: 8,
            max_pending_requests: 1,
            max_streams: 3,
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
        advertised: None,
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
        if !self.imports.is_empty() {
            self.import_next(&now).await?;
        } else if self.requested.is_none() {
            self.import_repaired(&now).await?;
        }
        if self.handshaken
            && self.requested.is_none()
            && !self.repair_ready
            && self.imports.is_empty()
        {
            self.request_blocks().await?;
        }
        self.wait().await
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
        if let Some(id) = InFlight::timed_out(&self.requested, now) {
            let _ = self
                .connection
                .cancel_request(id, net::RequestError::Timeout);
            return Err(End::BlockTimeout);
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
        let mut index = 0;
        while index < self.streams.len() {
            let stream = &mut self.streams[index];
            let request = stream.request;
            let mut access = self.platform.read_write_access(stream.stream.as_mut()).ok();
            if access.is_none() {
                drop(access);
                if InFlight::holds(&self.requested, request) {
                    if let Some(event) = self
                        .connection
                        .substream_reset(stream.id, net::RequestError::Rejected)
                    {
                        events.push(event);
                    }
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
            if rw.incoming_buffer.len() > FRAME_BYTES + 4 || rw.write_bytes_queued > 65536 {
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
            let retired = progress.reset
                || matches!(
                    &progress.event,
                    Some(net::Event::BlockResponse { .. } | net::Event::RequestFailed { .. })
                );
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
        Ok(events)
    }

    /// Handles one event of the connection.
    async fn handle(&mut self, event: net::Event) -> Result<(), End> {
        match event {
            net::Event::HandshakeReceived(h) => {
                self.handshake(h).await;
                Ok(())
            }
            net::Event::Announcement(a) => self.announcement(a).await,
            net::Event::BlockResponse { request_id, blocks } => {
                self.block_response(request_id, blocks).await
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
    async fn wait(&mut self) -> Result<(), End> {
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
                    || *repair_ready
                    || !imports.is_empty()
                    || (requested.is_none() && !announcements.is_empty())
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
                    net::SubstreamKind::Ce128 { request_id } => Some(request_id),
                    _ => None,
                };
                if self.connection.substream_opened(id, kind).is_err() {
                    let _ = self.connection.outgoing_open_failed(kind);
                    return Err(End::ProtocolError);
                }
                matches!(kind, net::SubstreamKind::Ce128 { .. })
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
        let pending = [self.requested.map(|r| {
            (
                "jam-block-request-ended",
                r.tag,
                r.queued,
                End::BlockTimeout,
            )
        })];
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
    }
}
