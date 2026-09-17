// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bounded, sans-io JAMNP-S UP0 and block-sequence CE128 initiator.
//!
//! The transport supplies authenticated bidirectional streams. Only their opener
//! sends a kind byte. Call [`Connection::desired_outgoing_substreams`], then report
//! either opening success or failure exactly once. Stream IDs are caller tokens,
//! not QUIC IDs: never reuse an ID while a callback for its old stream can arrive.
//! Duplicate UP0 streams retain the first, deliberately differing from JAMNP-S's
//! greatest-QUIC-ID rule because platform streams don't expose QUIC IDs.
//! A reserved local UP0 already counts as the first; later incoming UP0s are reset.
//!
//! [`Connection::read_write`] consumes borrowed input and fills bounded output.
//! Deliver its output in order; commit `finish_write` after those bytes, before
//! calling again. `peer_fin` means FIN follows the entire supplied input, and must
//! remain set when re-presenting unconsumed bytes. Poll again after events, even
//! with empty input, to observe FIN. Reset streams when `reset` is returned.
//! There is no event queue. An [`Event::ProtocolError`] is terminal: drop the
//! transport and fail all outstanding requests in the caller. [`Error::Protocol`]
//! reports a local API failure and does not close the connection. Returned headers
//! are structurally decoded, NOT consensus-verified. Extrinsics are structurally
//! delimited and retained as opaque bodies; their commitments are not checked.
//!
//! Memory is O(max_streams * max_message_size + max_pending_requests), plus decoded
//! objects bounded by the frame and Params. Output backpressure retains at most
//! one outgoing frame per stream. The caller must bound transport buffers and
//! event retention, and enforce open, handshake, response and idle deadlines via
//! cancellation/reset APIs or dropping the connection. No I/O or clock is owned.

mod ce128;
mod framing;
mod up0;

use crate::jam::{
    codec::DecodeError,
    params::Params,
    types::{Announcement, Block, BlockRequest, Handshake},
};
use alloc::{boxed::Box, vec::Vec};

/// Caller-assigned transport token.
pub type SubstreamId = u64;

/// Monotonic, connection-local request token; never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(u64);

/// Hard local budgets, including streams waiting for their kind byte.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum payload bytes, excluding kind and LE32 prefix, in either direction.
    pub max_message_size: usize,
    /// Maximum aggregate opaque body bytes in one returned block sequence.
    pub max_body_bytes: usize,
    /// Maximum local or remote handshake leaves.
    pub max_leaves_in_handshake: usize,
    /// Counts queued, opening and active requests together.
    pub max_pending_requests: usize,
    /// Counts incoming, active and reserved outgoing streams together.
    pub max_streams: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// An opening reservation issued by the connection, not a wire message.
pub enum SubstreamKind {
    Up0,
    Ce128 { request_id: RequestId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Protocol, codec or frame-allocation failure. Terminal when delivered as
/// [`Event::ProtocolError`]: drop the whole connection. When returned through
/// [`Error::Protocol`], this is a local API failure and the connection stays open.
pub enum ProtocolError {
    MessageTooLarge,
    AllocationFailed,
    Decode(DecodeError),
    UnexpectedFin,
    TrailingResponse,
    ResponseMismatch,
    Up0Lost,
}

/// Local API errors do not poison the connection or consume reservations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Closed,
    Limit,
    InvalidRequest,
    InvalidState,
    IdExhausted,
    Protocol(ProtocolError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Request termination without a block. Timeouts are decided by the caller.
pub enum RequestError {
    /// The peer returned a valid empty block sequence and cleanly finished.
    NoBlocks,
    Rejected,
    Cancelled,
    OpenFailed,
    Timeout,
}

#[derive(Debug, PartialEq, Eq)]
/// One owned notification; no internal event backlog is retained.
// UP0 announcements stay inline to avoid an allocation per header. CE128 now
// owns a Vec, so the largest variant is the announcement rather than a block.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    HandshakeReceived(Handshake),
    Announcement(Announcement),
    BlockResponse {
        request_id: RequestId,
        blocks: Vec<Block>,
    },
    RequestFailed {
        request_id: RequestId,
        reason: RequestError,
    },
    ProtocolError(ProtocolError),
}

/// Result of one bounded drive operation. At most one event is produced.
#[derive(Default, Debug)]
#[must_use]
pub struct Progress {
    /// Prefix of the supplied input consumed by this call.
    pub read: usize,
    /// Prefix of the supplied output initialized with outgoing bytes.
    pub written: usize,
    /// Send FIN after this call's output; reported exactly once per CE stream.
    pub finish_write: bool,
    /// Abort both stream halves. No further callbacks are required.
    pub reset: bool,
    pub event: Option<Event>,
}

struct Pending {
    id: RequestId,
    request: BlockRequest,
    opening: bool,
}
enum Stream {
    Incoming,
    Up0(up0::Up0),
    Ce128(Box<ce128::Ce128>),
}
#[derive(PartialEq, Eq)]
enum UpState {
    Needed,
    Opening,
    Active,
}

/// One connection. Construction validates the local handshake against budgets.
pub struct Connection {
    params: Params,
    limits: Limits,
    handshake: Vec<u8>,
    up: UpState,
    streams: Vec<(SubstreamId, Stream)>,
    pending: Vec<Pending>,
    next_request: u64,
    closed: bool,
}

impl Connection {
    /// Creates a connection ready to reserve UP0. Requires at least one stream
    /// slot and a message budget of at least 37 bytes (the CE128 request size).
    /// Zero pending-request capacity disables requests. Parameters are assumed
    /// to have been validated by chain configuration, as for the A1 codec.
    pub fn new(params: Params, handshake: Handshake, limits: Limits) -> Result<Self, Error> {
        if limits.max_streams == 0
            || limits.max_message_size < 37
            || handshake.leaves.len() > limits.max_leaves_in_handshake
            || handshake
                .leaves
                .len()
                .checked_mul(36)
                .and_then(|n| n.checked_add(36))
                .is_none_or(|n| n > limits.max_message_size)
        {
            return Err(Error::Limit);
        }
        let handshake = handshake.encode();
        if handshake.len() > limits.max_message_size || u32::try_from(handshake.len()).is_err() {
            return Err(Error::Limit);
        }
        Ok(Self {
            params,
            limits,
            handshake,
            up: UpState::Needed,
            streams: Vec::new(),
            pending: Vec::new(),
            next_request: 0,
            closed: false,
        })
    }

    fn occupied(&self) -> usize {
        self.streams
            .len()
            .saturating_add(self.pending.iter().filter(|p| p.opening).count())
            .saturating_add(usize::from(self.up == UpState::Opening))
    }

    /// Reserves an outgoing stream slot. Always resolve returned reservations,
    /// including platform opening errors, or they continue to consume capacity.
    pub fn desired_outgoing_substreams(&mut self) -> Option<SubstreamKind> {
        if self.closed || self.occupied() >= self.limits.max_streams {
            return None;
        }
        if self.up == UpState::Needed {
            self.up = UpState::Opening;
            return Some(SubstreamKind::Up0);
        }
        let pending = self.pending.iter_mut().find(|p| !p.opening)?;
        pending.opening = true;
        Some(SubstreamKind::Ce128 {
            request_id: pending.id,
        })
    }

    /// Registers an outgoing stream. On API error, reset the unregistered stream
    /// and resolve its reservation with `outgoing_open_failed` if still pending.
    pub fn substream_opened(&mut self, id: SubstreamId, kind: SubstreamKind) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.streams.iter().any(|(other, _)| *other == id) {
            return Err(Error::InvalidState);
        }
        self.streams.try_reserve(1).map_err(|_| Error::Limit)?;
        let stream = match kind {
            SubstreamKind::Up0 => {
                if self.up != UpState::Opening {
                    return Err(Error::InvalidState);
                }
                let stream = up0::Up0::new(&self.handshake, true, self.limits.max_message_size)
                    .map_err(Error::Protocol)?;
                self.up = UpState::Active;
                Stream::Up0(stream)
            }
            SubstreamKind::Ce128 { request_id } => {
                let position = self
                    .pending
                    .iter()
                    .position(|p| p.id == request_id && p.opening)
                    .ok_or(Error::InvalidState)?;
                let stream = ce128::Ce128::new(
                    request_id,
                    self.pending[position].request.clone(),
                    self.limits.max_message_size,
                )
                .map_err(Error::Protocol)?;
                self.pending.remove(position);
                Stream::Ce128(Box::new(stream))
            }
        };
        self.streams.push((id, stream));
        Ok(())
    }

    /// Opening UP0 failure is terminal; CE failure frees its request and slot.
    pub fn outgoing_open_failed(&mut self, kind: SubstreamKind) -> Result<Event, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        match kind {
            SubstreamKind::Up0 if self.up == UpState::Opening => {
                Ok(self.fail(ProtocolError::Up0Lost))
            }
            SubstreamKind::Ce128 { request_id } => {
                let position = self
                    .pending
                    .iter()
                    .position(|p| p.id == request_id && p.opening)
                    .ok_or(Error::InvalidState)?;
                self.pending.remove(position);
                Ok(Event::RequestFailed {
                    request_id,
                    reason: RequestError::OpenFailed,
                })
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Registers a peer stream awaiting its kind. On error reset it immediately.
    pub fn substream_incoming(&mut self, id: SubstreamId) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.streams.iter().any(|(other, _)| *other == id) {
            return Err(Error::InvalidState);
        }
        if self.occupied() >= self.limits.max_streams {
            return Err(Error::Limit);
        }
        self.streams.try_reserve(1).map_err(|_| Error::Limit)?;
        self.streams.push((id, Stream::Incoming));
        Ok(())
    }

    /// Queues a non-empty bounded block request. Responses may stop early.
    /// Peer NoData resets are reported through `substream_reset`.
    pub fn request_blocks(&mut self, request: BlockRequest) -> Result<RequestId, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if request.max_blocks == 0 {
            return Err(Error::InvalidRequest);
        }
        let active = self
            .streams
            .iter()
            .filter(|(_, s)| matches!(s, Stream::Ce128(_)))
            .count();
        if active.saturating_add(self.pending.len()) >= self.limits.max_pending_requests {
            return Err(Error::Limit);
        }
        let next = self.next_request.checked_add(1).ok_or(Error::IdExhausted)?;
        self.pending.try_reserve(1).map_err(|_| Error::Limit)?;
        let id = RequestId(self.next_request);
        self.next_request = next;
        self.pending.push(Pending {
            id,
            request,
            opening: false,
        });
        Ok(id)
    }

    /// Queues one encoded announcement, validating it before sending. Busy UP0
    /// returns `InvalidState`, providing backpressure instead of an unbounded queue.
    pub fn send_announcement(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if payload.len() > self.limits.max_message_size {
            return Err(Error::Limit);
        }
        Announcement::decode(&self.params, payload)
            .map_err(|e| Error::Protocol(ProtocolError::Decode(e)))?;
        let up = self
            .streams
            .iter_mut()
            .find_map(|(_, s)| match s {
                Stream::Up0(up) => Some(up),
                _ => None,
            })
            .ok_or(Error::InvalidState)?;
        if !up.writer.is_empty() {
            return Err(Error::InvalidState);
        }
        up.writer = framing::Writer::new(None, payload, self.limits.max_message_size)
            .map_err(Error::Protocol)?;
        Ok(())
    }

    /// Removes queued/opening/active requests. Reset the returned transport ID;
    /// cancel any opening operation (reset a late successful opening yourself).
    pub fn cancel_request(
        &mut self,
        request_id: RequestId,
        reason: RequestError,
    ) -> Result<(Option<SubstreamId>, Event), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if let Some(position) = self.pending.iter().position(|p| p.id == request_id) {
            self.pending.remove(position);
            return Ok((None, Event::RequestFailed { request_id, reason }));
        }
        let position = self
            .streams
            .iter()
            .position(|(_, s)| matches!(s, Stream::Ce128(c) if c.id == request_id))
            .ok_or(Error::InvalidState)?;
        let (id, _) = self.streams.remove(position);
        Ok((Some(id), Event::RequestFailed { request_id, reason }))
    }

    /// Reports peer reset, or caller timeout/abort (caller resets the transport).
    /// Unknown/retired IDs are harmless. UP0 loss is connection-fatal.
    pub fn substream_reset(&mut self, id: SubstreamId, reason: RequestError) -> Option<Event> {
        let position = self.streams.iter().position(|(other, _)| *other == id)?;
        match self.streams.remove(position).1 {
            Stream::Incoming => None,
            Stream::Up0(_) => Some(self.fail(ProtocolError::Up0Lost)),
            Stream::Ce128(c) => Some(Event::RequestFailed {
                request_id: c.id,
                reason,
            }),
        }
    }

    fn fail(&mut self, error: ProtocolError) -> Event {
        self.closed = true;
        self.streams.clear();
        self.pending.clear();
        Event::ProtocolError(error)
    }

    /// Drives one stream with at most one decoded event. Unknown/retired IDs
    /// request reset without allocating state. See module-level FIN obligations.
    pub fn read_write(
        &mut self,
        id: SubstreamId,
        input: &[u8],
        peer_fin: bool,
        output: &mut [u8],
    ) -> Progress {
        let mut progress = Progress::default();
        let Some(position) = self.streams.iter().position(|(other, _)| *other == id) else {
            progress.reset = true;
            return progress;
        };
        let mut remaining = input;
        if matches!(self.streams[position].1, Stream::Incoming) {
            let Some((&kind, rest)) = remaining.split_first() else {
                if peer_fin {
                    self.streams.remove(position);
                    progress.reset = true;
                }
                return progress;
            };
            remaining = rest;
            progress.read = 1;
            if kind != 0 || self.up != UpState::Needed {
                self.streams.remove(position);
                progress.reset = true;
                return progress;
            }
            match up0::Up0::new(&self.handshake, false, self.limits.max_message_size) {
                Ok(up) => {
                    self.streams[position].1 = Stream::Up0(up);
                    self.up = UpState::Active;
                }
                Err(error) => {
                    progress.event = Some(self.fail(error));
                    progress.reset = true;
                    return progress;
                }
            }
        }
        let result = match &mut self.streams[position].1 {
            Stream::Incoming => Ok(None),
            Stream::Up0(up) => {
                progress.written = up.writer.write(output);
                up.read(&mut remaining, peer_fin, &self.params, &self.limits)
            }
            Stream::Ce128(ce) => {
                progress.written = ce.writer.write(output);
                if ce.writer.is_empty() && !ce.fin_sent {
                    ce.fin_sent = true;
                    progress.finish_write = true;
                    // Wait until the caller has committed FIN before reporting success.
                    Ok(None)
                } else {
                    ce.read(&mut remaining, peer_fin, &self.params, &self.limits)
                }
            }
        };
        progress.read = input.len() - remaining.len();
        match result {
            Ok(event) => {
                if matches!(
                    event,
                    Some(Event::BlockResponse { .. } | Event::RequestFailed { .. })
                ) {
                    self.streams.remove(position);
                }
                progress.event = event;
            }
            Err(error) => {
                progress.event = Some(self.fail(error));
                progress.reset = true;
            }
        }
        progress
    }
}

#[cfg(test)]
mod tests;
