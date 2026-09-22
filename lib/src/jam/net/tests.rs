// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::codec::fixtures::{Ce128, Corruption, captured_ce128};
use crate::jam::types::{Direction, Final, Header};
use alloc::vec;
use rstest::rstest;

fn params() -> Params {
    let mut p = Params::from_protocol_parameters(&{
        let mut bytes = [0; 122];
        bytes[24] = 2;
        bytes
    })
    .unwrap();
    p.epoch_len = 12;
    p.max_validators = 6;
    p
}

fn limits() -> Limits {
    Limits {
        max_message_size: 4096,
        max_body_bytes: 32,
        max_leaves_in_handshake: 2,
        max_pending_requests: 2,
        max_streams: 4,
    }
}

fn handshake() -> Handshake {
    Handshake {
        final_: Final {
            hash: [4; 32],
            slot: 3,
        },
        leaves: vec![],
    }
}

fn block() -> Block {
    Block {
        header: Header {
            parent: [7; 32],
            prior_state_root: [8; 32],
            extrinsic_hash: [9; 32],
            slot: 4,
            epoch_mark: None,
            tickets_mark: None,
            author_index: 0,
            entropy_source: [0; 96],
            offenders_mark: vec![],
            seal: [0; 96],
        },
        body: vec![0; 7],
    }
}

fn request() -> BlockRequest {
    BlockRequest {
        hash: block().header.hash(&params()),
        direction: Direction::DescendingInclusive,
        max_blocks: 1,
    }
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn connection() -> Connection {
    Connection::new(params(), handshake(), limits()).unwrap()
}

fn open_up(c: &mut Connection) {
    assert_eq!(c.desired_outgoing_substreams(), Some(SubstreamKind::Up0));
    c.substream_opened(1, SubstreamKind::Up0).unwrap();
}

fn open_ce(c: &mut Connection, req: BlockRequest) -> RequestId {
    let id = c.request_blocks(req).unwrap();
    let kind = SubstreamKind::Ce128 { request_id: id };
    assert_eq!(c.desired_outgoing_substreams(), Some(kind));
    c.substream_opened(2, kind).unwrap();
    id
}

fn drain(c: &mut Connection, id: SubstreamId, width: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut finished = false;
    loop {
        let mut out = vec![0; width];
        let p = c.read_write(id, &[], false, &mut out);
        assert!(p.event.is_none());
        assert!(!p.reset);
        bytes.extend_from_slice(&out[..p.written]);
        if p.finish_write {
            assert!(!finished);
            finished = true;
        }
        if p.written == 0 {
            break;
        }
    }
    (bytes, finished)
}

fn feed(c: &mut Connection, id: SubstreamId, bytes: &[u8], width: usize) -> Vec<Event> {
    let mut events = Vec::new();
    for chunk in bytes.chunks(width) {
        let mut input = chunk;
        while !input.is_empty() {
            let p = c.read_write(id, input, false, &mut []);
            assert!(!p.reset, "{p:?}");
            assert!(p.read > 0);
            input = &input[p.read..];
            events.extend(p.event);
        }
    }
    events
}

#[test]
fn scripted_peer_fragmentation_and_both_up0_directions() {
    let announcement = Announcement {
        header: block().header,
        final_: handshake().final_,
    };
    let mut peer = frame(&handshake().encode());
    peer.extend(frame(&announcement.encode(&params())));
    peer.extend(frame(&announcement.encode(&params())));
    for width in [1, 2, 3, 4, 5, 37, 4096] {
        for incoming in [false, true] {
            let mut c = connection();
            if incoming {
                c.substream_incoming(1).unwrap();
                assert_eq!(c.read_write(1, &[0], false, &mut []).read, 1);
                assert_eq!(c.desired_outgoing_substreams(), None);
            } else {
                open_up(&mut c);
            }
            let payload = announcement.encode(&params());
            assert_eq!(c.send_announcement(&payload), Err(Error::InvalidState));
            let (wire, fin) = drain(&mut c, 1, width);
            let mut expected = vec![];
            if !incoming {
                expected.push(0);
            }
            expected.extend(frame(&handshake().encode()));
            assert_eq!(wire, expected);
            assert!(!fin);
            assert_eq!(
                feed(&mut c, 1, &peer, width),
                vec![
                    Event::HandshakeReceived(handshake()),
                    Event::Announcement(announcement.clone()),
                    Event::Announcement(announcement.clone())
                ]
            );
            c.send_announcement(&payload).unwrap();
            assert_eq!(c.send_announcement(&payload), Err(Error::InvalidState));
            assert_eq!(drain(&mut c, 1, width), (frame(&payload), false));
        }
    }
}

#[test]
fn ce128_single_block_requires_both_fins_and_binds_both_directions() {
    for width in [1, 2, 3, 4, 5, 41, 4096] {
        for direction in [
            Direction::AscendingExclusive,
            Direction::DescendingInclusive,
        ] {
            let mut c = connection();
            open_up(&mut c);
            let mut req = request();
            if direction == Direction::AscendingExclusive {
                req.hash = block().header.parent;
            }
            req.direction = direction;
            let id = open_ce(&mut c, req.clone());
            let response = frame(&block().encode(&params()));
            let stalled = c.read_write(2, &response, true, &mut []);
            assert_eq!(stalled.read, 0);
            assert!(!stalled.finish_write);
            assert!(stalled.event.is_none());
            let (wire, fin) = drain(&mut c, 2, width);
            let mut expected = vec![128];
            expected.extend(frame(&req.encode()));
            assert_eq!(wire, expected);
            assert!(fin);
            assert!(feed(&mut c, 2, &response, width).is_empty());
            assert!(c.read_write(2, &[], false, &mut []).event.is_none());
            let done = c.read_write(2, &[], true, &mut []);
            assert_eq!(
                done.event,
                Some(Event::BlockResponse {
                    request_id: id,
                    blocks: vec![block()]
                })
            );
            assert_eq!(c.streams.len(), 1);
            assert!(c.pending.is_empty());
            assert!(c.read_write(2, &[], true, &mut []).reset);
            assert_eq!(c.substream_reset(2, RequestError::Rejected), None);
        }
    }
}

#[test]
fn response_cannot_complete_in_fin_emitting_call() {
    let mut c = connection();
    open_up(&mut c);
    let id = open_ce(&mut c, request());
    let response = frame(&block().encode(&params()));
    let p = c.read_write(2, &response, true, &mut [0; 100]);
    assert_eq!(p.written, 42);
    assert!(p.finish_write);
    assert_eq!(p.read, 0);
    assert!(p.event.is_none());
    let p = c.read_write(2, &response, true, &mut []);
    assert_eq!(p.read, response.len());
    assert_eq!(
        p.event,
        Some(Event::BlockResponse {
            request_id: id,
            blocks: vec![block()]
        })
    );
}

#[test]
fn every_truncated_frame_is_terminal() {
    for ce in [false, true] {
        let wire = if ce {
            frame(&block().encode(&params()))
        } else {
            frame(&handshake().encode())
        };
        for end in 0..wire.len() {
            let mut c = connection();
            open_up(&mut c);
            let stream = if ce {
                open_ce(&mut c, request());
                drain(&mut c, 2, 10);
                2
            } else {
                1
            };
            let p = c.read_write(stream, &wire[..end], true, &mut []);
            assert_eq!(
                p.event,
                Some(Event::ProtocolError(ProtocolError::UnexpectedFin)),
                "end {end}"
            );
            assert!(p.reset);
            assert!(c.closed);
            assert!(c.streams.is_empty());
            assert!(c.pending.is_empty());
            assert_eq!(c.request_blocks(request()), Err(Error::Closed));
        }
    }
    let mut c = connection();
    open_up(&mut c);
    let id = open_ce(&mut c, request());
    drain(&mut c, 2, 42);
    assert_eq!(
        c.read_write(2, &[0; 4], true, &mut []).event,
        Some(Event::RequestFailed {
            request_id: id,
            reason: RequestError::NoBlocks
        })
    );
}

#[test]
fn empty_response_waits_for_both_fins_and_releases_only_its_request() {
    for direction in [
        Direction::AscendingExclusive,
        Direction::DescendingInclusive,
    ] {
        for width in 1..=4 {
            for fin_with_frame in [false, true] {
                let mut l = limits();
                l.max_streams = 3;
                let mut c = Connection::new(params(), handshake(), l).unwrap();
                open_up(&mut c);
                let mut req = request();
                req.direction = direction.clone();
                let empty_id = open_ce(&mut c, req);
                let other_id = c.request_blocks(request()).unwrap();
                let kind = c.desired_outgoing_substreams().unwrap();
                c.substream_opened(3, kind).unwrap();
                assert_eq!(c.request_blocks(request()), Err(Error::Limit));
                assert_eq!(c.substream_incoming(4), Err(Error::Limit));

                // Even an entire empty frame plus peer FIN cannot finish before local FIN.
                let p = c.read_write(2, &[0; 4], true, &mut []);
                assert_eq!(p.read, 0);
                assert!(!p.finish_write);
                assert!(p.event.is_none());
                let p = c.read_write(2, &[0; 4], true, &mut [0; 42]);
                assert!(p.finish_write);
                assert_eq!(p.read, 0);
                assert!(p.event.is_none());

                let mut event = None;
                let mut consumed = 0;
                for chunk in [0; 4].chunks(width) {
                    consumed += chunk.len();
                    let fin = fin_with_frame && consumed == 4;
                    let p = c.read_write(2, chunk, fin, &mut []);
                    assert_eq!(p.read, chunk.len());
                    assert!(!p.reset);
                    assert!(!p.finish_write);
                    if !fin {
                        assert!(p.event.is_none());
                        assert_eq!(c.request_blocks(request()), Err(Error::Limit));
                        assert!(c.read_write(2, &[], false, &mut []).event.is_none());
                    }
                    event = p.event;
                }
                if !fin_with_frame {
                    let p = c.read_write(2, &[], true, &mut []);
                    assert!(!p.reset);
                    event = p.event;
                }
                assert_eq!(
                    event,
                    Some(Event::RequestFailed {
                        request_id: empty_id,
                        reason: RequestError::NoBlocks,
                    })
                );
                assert!(!c.closed);
                assert_eq!(c.occupied(), 2);
                assert_eq!(
                    c.cancel_request(empty_id, RequestError::Cancelled),
                    Err(Error::InvalidState)
                );
                assert_eq!(c.substream_reset(2, RequestError::Rejected), None);

                // Both request and stream capacity are available immediately after FIN.
                let replacement = c.request_blocks(request()).unwrap();
                let kind = c.desired_outgoing_substreams().unwrap();
                assert_eq!(
                    kind,
                    SubstreamKind::Ce128 {
                        request_id: replacement
                    }
                );
                c.substream_opened(4, kind).unwrap();

                // The independent UP0 exchange and existing CE request still succeed.
                drain(&mut c, 1, 1);
                assert_eq!(
                    feed(&mut c, 1, &frame(&handshake().encode()), 1),
                    vec![Event::HandshakeReceived(handshake())]
                );
                let a = Announcement {
                    header: block().header,
                    final_: handshake().final_,
                };
                assert_eq!(
                    feed(&mut c, 1, &frame(&a.encode(&params())), 1),
                    vec![Event::Announcement(a)]
                );
                drain(&mut c, 3, 1);
                assert_eq!(
                    c.read_write(3, &frame(&block().encode(&params())), true, &mut [])
                        .event,
                    Some(Event::BlockResponse {
                        request_id: other_id,
                        blocks: vec![block()]
                    })
                );
                assert_eq!(
                    c.cancel_request(replacement, RequestError::Cancelled)
                        .unwrap()
                        .0,
                    Some(4)
                );
                assert_eq!(c.occupied(), 1);
            }
        }
    }
}

#[test]
fn empty_response_rejects_same_call_or_later_trailing_bytes() {
    for direction in [
        Direction::AscendingExclusive,
        Direction::DescendingInclusive,
    ] {
        for together in [false, true] {
            for fin in [false, true] {
                // Neither arbitrary trailing bytes nor another valid frame are allowed.
                for trailing in [vec![42], vec![0; 4], frame(&block().encode(&params()))] {
                    let mut c = connection();
                    open_up(&mut c);
                    let mut req = request();
                    req.direction = direction.clone();
                    open_ce(&mut c, req);
                    drain(&mut c, 2, 1);
                    let mut wire = vec![];
                    if together {
                        wire.extend_from_slice(&[0; 4]);
                    } else {
                        assert!(feed(&mut c, 2, &[0; 4], 1).is_empty());
                        assert!(c.read_write(2, &[], false, &mut []).event.is_none());
                    }
                    wire.extend_from_slice(&trailing);
                    let p = c.read_write(2, &wire, fin, &mut []);
                    assert_eq!(
                        p.event,
                        Some(Event::ProtocolError(ProtocolError::TrailingResponse))
                    );
                    assert!(p.reset);
                    assert!(c.closed);
                }
            }
        }
    }
}

#[test]
fn missing_or_truncated_empty_frame_prefix_is_still_terminal() {
    for direction in [
        Direction::AscendingExclusive,
        Direction::DescendingInclusive,
    ] {
        for length in 0..4 {
            let mut c = connection();
            open_up(&mut c);
            let mut req = request();
            req.direction = direction.clone();
            open_ce(&mut c, req);
            drain(&mut c, 2, 1);
            assert!(feed(&mut c, 2, &[0; 4][..length], 1).is_empty());
            let p = c.read_write(2, &[], true, &mut []);
            assert_eq!(
                p.event,
                Some(Event::ProtocolError(ProtocolError::UnexpectedFin))
            );
            assert!(p.reset);
            assert!(c.closed);
        }
    }
}

#[test]
fn malformed_payloads_oversize_and_trailing_frames() {
    for payload in [vec![], vec![0; 36], vec![0; 38], vec![255; 45]] {
        let mut c = connection();
        open_up(&mut c);
        assert!(matches!(
            c.read_write(1, &frame(&payload), false, &mut []).event,
            Some(Event::ProtocolError(ProtocolError::Decode(_)))
        ));
    }
    for ce in [false, true] {
        let mut c = connection();
        open_up(&mut c);
        let id = if ce {
            open_ce(&mut c, request());
            drain(&mut c, 2, 42);
            2
        } else {
            1
        };
        assert_eq!(
            c.read_write(id, &u32::MAX.to_le_bytes(), false, &mut [])
                .event,
            Some(Event::ProtocolError(ProtocolError::MessageTooLarge))
        );
    }
    for together in [false, true] {
        let mut c = connection();
        open_up(&mut c);
        open_ce(&mut c, request());
        drain(&mut c, 2, 42);
        let mut wire = frame(&block().encode(&params()));
        if together {
            wire.push(0);
        } else {
            assert!(feed(&mut c, 2, &wire, 1).is_empty());
            wire = vec![0];
        }
        assert_eq!(
            c.read_write(2, &wire, true, &mut []).event,
            Some(Event::ProtocolError(ProtocolError::TrailingResponse))
        );
    }
    for direction in [
        Direction::AscendingExclusive,
        Direction::DescendingInclusive,
    ] {
        let mut c = connection();
        open_up(&mut c);
        let mut req = request();
        req.hash = [42; 32];
        req.direction = direction;
        open_ce(&mut c, req);
        drain(&mut c, 2, 42);
        assert_eq!(
            c.read_write(2, &frame(&block().encode(&params())), true, &mut [])
                .event,
            Some(Event::ProtocolError(ProtocolError::ResponseMismatch))
        );
    }
}

#[test]
fn every_budget_at_boundary_and_over_limit() {
    for max in [0, 36] {
        let mut l = limits();
        l.max_message_size = max;
        assert!(matches!(
            Connection::new(params(), handshake(), l),
            Err(Error::Limit)
        ));
    }
    let mut l = limits();
    l.max_message_size = 37;
    l.max_leaves_in_handshake = 0;
    let mut c = Connection::new(params(), handshake(), l.clone()).unwrap();
    open_up(&mut c);
    assert_eq!(
        feed(&mut c, 1, &frame(&handshake().encode()), 1),
        vec![Event::HandshakeReceived(handshake())]
    );
    assert_eq!(
        c.read_write(1, &38u32.to_le_bytes(), false, &mut []).event,
        Some(Event::ProtocolError(ProtocolError::MessageTooLarge))
    );
    let mut h = handshake();
    h.leaves.push(h.final_.clone());
    assert!(matches!(
        Connection::new(params(), h.clone(), l),
        Err(Error::Limit)
    ));
    for leaves in [0, 1, 2, 3] {
        let mut c = connection();
        open_up(&mut c);
        h.leaves = vec![h.final_.clone(); leaves];
        let event = c.read_write(1, &frame(&h.encode()), false, &mut []).event;
        if leaves <= 2 {
            assert_eq!(event, Some(Event::HandshakeReceived(h.clone())));
        } else {
            assert_eq!(
                event,
                Some(Event::ProtocolError(ProtocolError::Decode(
                    DecodeError::LengthLimit
                )))
            );
        }
    }
    for body_limit in [0, 6, 7, 8] {
        let mut l = limits();
        l.max_body_bytes = body_limit;
        let mut c = Connection::new(params(), handshake(), l).unwrap();
        open_up(&mut c);
        let id = open_ce(&mut c, request());
        drain(&mut c, 2, 42);
        let event = c
            .read_write(2, &frame(&block().encode(&params())), true, &mut [])
            .event;
        if body_limit >= 7 {
            assert_eq!(
                event,
                Some(Event::BlockResponse {
                    request_id: id,
                    blocks: vec![block()]
                })
            );
        } else {
            assert_eq!(
                event,
                Some(Event::ProtocolError(ProtocolError::Decode(
                    DecodeError::LengthLimit
                )))
            );
        }
    }
    let mut l = limits();
    l.max_pending_requests = 0;
    let mut c = Connection::new(params(), handshake(), l).unwrap();
    assert_eq!(c.request_blocks(request()), Err(Error::Limit));
    let mut l = limits();
    l.max_streams = 0;
    assert!(matches!(
        Connection::new(params(), handshake(), l),
        Err(Error::Limit)
    ));
    let mut l = limits();
    l.max_streams = 1;
    let mut c = Connection::new(params(), handshake(), l).unwrap();
    assert_eq!(c.desired_outgoing_substreams(), Some(SubstreamKind::Up0));
    assert_eq!(c.substream_incoming(9), Err(Error::Limit));
    c.substream_opened(1, SubstreamKind::Up0).unwrap();
    c.request_blocks(request()).unwrap();
    assert_eq!(c.desired_outgoing_substreams(), None);
}

#[test]
fn request_lifecycle_cleanup_and_reservation_accounting() {
    let mut c = connection();
    open_up(&mut c);
    for iteration in 0..1000 {
        let a = c.request_blocks(request()).unwrap();
        let b = c.request_blocks(request()).unwrap();
        assert_ne!(a, b);
        assert_eq!(c.request_blocks(request()), Err(Error::Limit));
        assert_eq!(
            c.cancel_request(b, RequestError::Cancelled).unwrap().0,
            None
        );
        let kind = c.desired_outgoing_substreams().unwrap();
        assert_eq!(kind, SubstreamKind::Ce128 { request_id: a });
        assert_eq!(c.desired_outgoing_substreams(), None);
        match iteration % 4 {
            0 => assert_eq!(
                c.outgoing_open_failed(kind).unwrap(),
                Event::RequestFailed {
                    request_id: a,
                    reason: RequestError::OpenFailed
                }
            ),
            1 => {
                c.cancel_request(a, RequestError::Timeout).unwrap();
                assert_eq!(c.substream_opened(2, kind), Err(Error::InvalidState));
            }
            2 => {
                c.substream_opened(2, kind).unwrap();
                assert_eq!(
                    c.substream_reset(2, RequestError::Rejected),
                    Some(Event::RequestFailed {
                        request_id: a,
                        reason: RequestError::Rejected
                    })
                );
            }
            _ => {
                c.substream_opened(2, kind).unwrap();
                drain(&mut c, 2, 1);
                feed(&mut c, 2, &frame(&block().encode(&params())), 1);
                assert_eq!(
                    c.cancel_request(a, RequestError::Timeout).unwrap().0,
                    Some(2)
                );
            }
        }
        assert_eq!(
            c.cancel_request(a, RequestError::Cancelled),
            Err(Error::InvalidState)
        );
        assert_eq!(c.outgoing_open_failed(kind), Err(Error::InvalidState));
        assert!(c.pending.is_empty());
        assert_eq!(c.streams.len(), 1);
        assert_eq!(c.occupied(), 1);
    }
    for max in [0] {
        let mut req = request();
        req.max_blocks = max;
        assert_eq!(c.request_blocks(req), Err(Error::InvalidRequest));
    }
    c.next_request = u64::MAX;
    assert_eq!(c.request_blocks(request()), Err(Error::IdExhausted));
}

#[test]
fn incoming_stream_limits_rejection_duplicates_and_up0_loss() {
    let mut c = connection();
    for id in 0..4 {
        c.substream_incoming(id).unwrap();
    }
    assert_eq!(c.substream_incoming(4), Err(Error::Limit));
    assert_eq!(c.desired_outgoing_substreams(), None);
    assert_eq!(c.substream_incoming(0), Err(Error::InvalidState));
    assert!(c.read_write(0, &[], true, &mut []).reset);
    assert!(c.read_write(1, &[128], false, &mut []).reset);
    assert!(c.read_write(2, &[255], false, &mut []).reset);
    let p = c.read_write(3, &[0], false, &mut []);
    assert!(!p.reset);
    for id in 4..1000 {
        c.substream_incoming(id).unwrap();
        assert!(c.read_write(id, &[0], false, &mut []).reset);
        assert_eq!(c.streams.len(), 1);
    }
    assert_eq!(
        c.substream_reset(3, RequestError::Rejected),
        Some(Event::ProtocolError(ProtocolError::Up0Lost))
    );
    assert!(c.streams.is_empty());
    assert_eq!(c.substream_incoming(1001), Err(Error::Closed));
    assert_eq!(c.desired_outgoing_substreams(), None);
    let mut c = connection();
    let kind = c.desired_outgoing_substreams().unwrap();
    assert_eq!(
        c.outgoing_open_failed(kind),
        Ok(Event::ProtocolError(ProtocolError::Up0Lost))
    );
}

#[test]
fn up0_fin_and_invalid_announcements() {
    let mut c = connection();
    open_up(&mut c);
    assert_eq!(
        c.read_write(1, &frame(&handshake().encode()), true, &mut [])
            .event,
        Some(Event::HandshakeReceived(handshake()))
    );
    assert_eq!(
        c.read_write(1, &[], true, &mut []).event,
        Some(Event::ProtocolError(ProtocolError::UnexpectedFin))
    );
    let mut c = connection();
    open_up(&mut c);
    drain(&mut c, 1, 1);
    assert!(matches!(
        c.send_announcement(&[]),
        Err(Error::Protocol(ProtocolError::Decode(_)))
    ));
    assert_eq!(c.send_announcement(&vec![0; 4097]), Err(Error::Limit));
    feed(&mut c, 1, &frame(&handshake().encode()), 1);
    assert!(matches!(
        c.read_write(1, &frame(&handshake().encode()), false, &mut [])
            .event,
        Some(Event::ProtocolError(ProtocolError::Decode(_)))
    ));
}

#[test]
fn fuzz_style_random_and_mutated_streams_remain_bounded() {
    let mut seed = 0x1234_5678u32;
    for iteration in 0..5000 {
        let mut c = connection();
        open_up(&mut c);
        let ce = iteration % 2 == 0;
        let id = if ce {
            open_ce(&mut c, request());
            drain(&mut c, 2, 42);
            2
        } else {
            1
        };
        let mut bytes = if ce {
            frame(&block().encode(&params()))
        } else {
            frame(&handshake().encode())
        };
        for _ in 0..1 + iteration % 8 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let index = usize::try_from(seed).unwrap() % bytes.len();
            bytes[index] = seed.to_le_bytes()[1];
        }
        if iteration % 5 == 0 {
            for byte in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *byte = seed.to_le_bytes()[0];
            }
        }
        if iteration % 3 == 0 {
            bytes.truncate(iteration % bytes.len());
        }
        for chunk in bytes.chunks(1 + iteration % 17) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let p = c.read_write(id, rest, false, &mut [0; 3]);
                assert!(p.read <= rest.len());
                assert!(p.written <= 3);
                if p.reset {
                    break;
                }
                assert!(p.read > 0);
                rest = &rest[p.read..];
            }
            if c.closed {
                break;
            }
        }
        let _ = c.read_write(id, &[], true, &mut []);
        assert!(c.streams.len() <= c.limits.max_streams);
        assert!(c.pending.len() <= c.limits.max_pending_requests);
    }
}

#[test]
fn active_and_opening_requests_share_capacity_and_cleanup() {
    let mut c = connection();
    open_up(&mut c);
    let a = open_ce(&mut c, request());
    let b = c.request_blocks(request()).unwrap();
    let kind = c.desired_outgoing_substreams().unwrap();
    assert_eq!(c.request_blocks(request()), Err(Error::Limit));
    c.substream_incoming(3).unwrap();
    assert_eq!(c.substream_incoming(4), Err(Error::Limit));
    // An ID collision does not consume b's opening reservation.
    assert_eq!(c.substream_opened(2, kind), Err(Error::InvalidState));
    assert_eq!(c.occupied(), 4);
    c.substream_opened(4, kind).unwrap();
    assert_eq!(c.occupied(), 4);
    assert_eq!(c.request_blocks(request()), Err(Error::Limit));
    assert_eq!(
        c.substream_reset(4, RequestError::Rejected),
        Some(Event::RequestFailed {
            request_id: b,
            reason: RequestError::Rejected,
        })
    );
    assert_eq!(c.substream_reset(4, RequestError::Rejected), None);
    drain(&mut c, 2, 1);
    feed(&mut c, 2, &frame(&block().encode(&params())), 1);
    assert_eq!(
        c.substream_reset(2, RequestError::Rejected),
        Some(Event::RequestFailed {
            request_id: a,
            reason: RequestError::Rejected,
        })
    );
    assert!(c.read_write(2, &[], true, &mut []).event.is_none());
    assert_eq!(c.substream_reset(3, RequestError::Timeout), None);
    assert_eq!(c.occupied(), 1);
    c.request_blocks(request()).unwrap();
    c.request_blocks(request()).unwrap();
}

#[test]
fn exact_response_budget_and_all_stream_kind_bytes() {
    let wire = frame(&block().encode(&params()));
    for max in [wire.len() - 5, wire.len() - 4] {
        let mut l = limits();
        l.max_message_size = max;
        let mut c = Connection::new(params(), handshake(), l).unwrap();
        open_up(&mut c);
        let id = open_ce(&mut c, request());
        drain(&mut c, 2, 1);
        let p = c.read_write(2, &wire, true, &mut []);
        if max == wire.len() - 4 {
            assert_eq!(
                p.event,
                Some(Event::BlockResponse {
                    request_id: id,
                    blocks: vec![block()]
                })
            );
        } else {
            assert_eq!(p.read, 4);
            assert_eq!(
                p.event,
                Some(Event::ProtocolError(ProtocolError::MessageTooLarge))
            );
        }
    }
    for kind in 0..=255 {
        let mut c = connection();
        c.substream_incoming(1).unwrap();
        let p = c.read_write(1, &[kind], false, &mut []);
        assert_eq!(p.read, 1);
        assert_eq!(p.reset, kind != 0);
        assert_eq!(c.streams.len(), usize::from(kind == 0));
    }
    let mut c = connection();
    assert_eq!(c.desired_outgoing_substreams(), Some(SubstreamKind::Up0));
    c.substream_incoming(9).unwrap();
    assert!(c.read_write(9, &[0], false, &mut []).reset);
    c.substream_opened(1, SubstreamKind::Up0).unwrap();
    assert_eq!(drain(&mut c, 1, 1).0[0], 0);
}

#[test]
#[ignore = "requires external A5 captures; set JAM_A5_FIXTURES or use documented absolute default"]
fn external_captured_frames() {
    use std::{fs, path::PathBuf};
    fn hex(value: &serde_json::Value) -> Vec<u8> {
        let text = value.as_str().unwrap();
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    let root = std::env::var_os("JAM_A5_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("/home/sebastian/work/repos/jam-light-client-planning/fixtures")
        });
    let json = |path: &str| -> serde_json::Value {
        serde_json::from_slice(&fs::read(root.join(path)).unwrap()).unwrap()
    };
    let p = Params::from_protocol_parameters(&hex(&json("params.json")["protocol_parameters"]))
        .unwrap();
    let up = json("messages/up0.json");
    let ce = json("messages/ce128.json");
    assert_eq!(up["protocol_preamble_in_frames"], false);
    assert_eq!(ce["protocol_preamble_in_frames"], false);
    assert_eq!(up["same_stream"], true);
    assert_eq!(ce["same_stream"], true);
    assert_eq!(ce["response_fin_received"], true);
    let handshake_frame = hex(&up["handshake_frame_hex"]);
    let announce_frame = hex(&up["announcement_frame_hex"]);
    let request_frame = hex(&ce["request_frame_hex"]);
    let response_frame = hex(&ce["response_frame_hex"]);
    for wire in [
        &handshake_frame,
        &announce_frame,
        &request_frame,
        &response_frame,
    ] {
        assert_eq!(
            usize::try_from(u32::from_le_bytes(wire[..4].try_into().unwrap())).unwrap(),
            wire.len() - 4
        );
    }
    let h = Handshake::decode(&handshake_frame[4..], 64).unwrap();
    let a = Announcement::decode(&p, &announce_frame[4..]).unwrap();
    let req = BlockRequest::decode(&request_frame[4..]).unwrap();
    assert_eq!(req.max_blocks, 1);
    let b = Block::decode(&p, &response_frame[4..], 4096).unwrap();
    assert_eq!(
        a.header.hash(&p).as_slice(),
        hex(&up["announcement_header_hash"])
    );
    assert_eq!(b.header.hash(&p).as_slice(), hex(&ce["block_hashes"][0]));
    for width in [1, 4096] {
        let mut l = limits();
        l.max_body_bytes = 4096;
        l.max_leaves_in_handshake = 64;
        let mut c = Connection::new(p.clone(), h.clone(), l).unwrap();
        open_up(&mut c);
        let (local, fin) = drain(&mut c, 1, width);
        assert!(!fin);
        assert_eq!(&local[1..], handshake_frame);
        let mut incoming = handshake_frame.clone();
        incoming.extend_from_slice(&announce_frame);
        assert_eq!(
            feed(&mut c, 1, &incoming, width),
            vec![
                Event::HandshakeReceived(h.clone()),
                Event::Announcement(a.clone())
            ]
        );
        let id = open_ce(&mut c, req.clone());
        let (local, fin) = drain(&mut c, 2, width);
        assert!(fin);
        assert_eq!(&local[1..], request_frame);
        assert!(feed(&mut c, 2, &response_frame, width).is_empty());
        assert_eq!(
            c.read_write(2, &[], true, &mut []).event,
            Some(Event::BlockResponse {
                request_id: id,
                blocks: vec![b.clone()]
            })
        );
    }
}

fn open_justification(c: &mut Connection) -> RequestId {
    let id = c.request_justification([42; 32]).unwrap();
    let kind = SubstreamKind::Ce130 { request_id: id };
    assert_eq!(c.desired_outgoing_substreams(), Some(kind));
    c.substream_opened(2, kind).unwrap();
    id
}

#[test]
fn ce130_fragmentation_and_fin_gate() {
    // Deliberately opaque: this layer must not claim consensus verification.
    let proof = vec![9; 300];
    for width in [1, 2, 4, 17, 4096] {
        let mut c = connection();
        open_up(&mut c);
        let id = open_justification(&mut c);
        let mut expected = vec![130];
        expected.extend(frame(&[42; 32]));
        assert_eq!(drain(&mut c, 2, width), (expected, true));
        assert!(feed(&mut c, 2, &frame(&proof), width).is_empty());
        assert!(c.read_write(2, &[], false, &mut []).event.is_none());
        assert_eq!(
            c.read_write(2, &[], true, &mut []).event,
            Some(Event::JustificationResponse {
                request_id: id,
                target: [42; 32],
                justification: proof.clone(),
            })
        );
        assert!(c.read_write(2, &[], true, &mut []).reset);
    }
}

#[test]
fn ce130_requires_request_fin_before_consuming_response() {
    let mut c = connection();
    open_up(&mut c);
    let id = open_justification(&mut c);
    let response = frame(&[3; 10]);
    let p = c.read_write(2, &response, true, &mut [0; 100]);
    assert!(p.finish_write);
    assert_eq!(p.read, 0);
    assert!(p.event.is_none());
    let p = c.read_write(2, &response, true, &mut []);
    assert!(!p.finish_write);
    assert_eq!(p.read, response.len());
    assert_eq!(
        p.event,
        Some(Event::JustificationResponse {
            request_id: id,
            target: [42; 32],
            justification: vec![3; 10],
        })
    );
}

#[test]
fn ce130_rejects_truncated_oversize_and_multiple_frames() {
    let mut cases = vec![
        (vec![], ProtocolError::UnexpectedFin),
        (vec![1, 0], ProtocolError::UnexpectedFin),
        (vec![3, 0, 0, 0, 1], ProtocolError::UnexpectedFin),
        (
            4097u32.to_le_bytes().to_vec(),
            ProtocolError::MessageTooLarge,
        ),
    ];
    let mut extra = frame(&[7; 10]);
    extra.extend(frame(&[8; 10]));
    cases.push((extra, ProtocolError::TrailingResponse));
    for (response, error) in cases {
        let mut c = connection();
        open_up(&mut c);
        open_justification(&mut c);
        drain(&mut c, 2, 100);
        let p = c.read_write(2, &response, true, &mut []);
        assert_eq!(p.event, Some(Event::ProtocolError(error)));
        assert!(p.reset);
        assert_eq!(c.request_justification([42; 32]), Err(Error::Closed));
    }
}

#[test]
fn ce130_shares_limits_and_checks_reservation_kind() {
    let mut c = connection();
    open_up(&mut c);
    let proof_id = c.request_justification([42; 32]).unwrap();
    let block_id = c.request_blocks(request()).unwrap();
    assert_eq!(c.request_justification([43; 32]), Err(Error::Limit));
    let kind = SubstreamKind::Ce130 {
        request_id: proof_id,
    };
    assert_eq!(c.desired_outgoing_substreams(), Some(kind));
    let wrong = SubstreamKind::Ce128 {
        request_id: proof_id,
    };
    assert_eq!(c.substream_opened(2, wrong), Err(Error::InvalidState));
    assert_eq!(c.outgoing_open_failed(wrong), Err(Error::InvalidState));
    c.substream_opened(2, kind).unwrap();
    assert_eq!(c.request_blocks(request()), Err(Error::Limit));
    assert_eq!(
        c.substream_reset(2, RequestError::Rejected),
        Some(Event::RequestFailed {
            request_id: proof_id,
            reason: RequestError::Rejected,
        })
    );
    assert_eq!(
        c.desired_outgoing_substreams(),
        Some(SubstreamKind::Ce128 {
            request_id: block_id
        })
    );
    c.request_justification([43; 32]).unwrap();
}

#[test]
fn ce130_cancel_and_open_failure_free_capacity() {
    for opening in [false, true] {
        let mut c = connection();
        open_up(&mut c);
        let id = c.request_justification([42; 32]).unwrap();
        let kind = SubstreamKind::Ce130 { request_id: id };
        if opening {
            assert_eq!(c.desired_outgoing_substreams(), Some(kind));
        }
        assert_eq!(
            c.cancel_request(id, RequestError::Timeout).unwrap(),
            (
                None,
                Event::RequestFailed {
                    request_id: id,
                    reason: RequestError::Timeout,
                }
            )
        );
        assert_eq!(c.substream_opened(2, kind), Err(Error::InvalidState));
        let id = c.request_justification([42; 32]).unwrap();
        let kind = c.desired_outgoing_substreams().unwrap();
        assert_eq!(
            c.outgoing_open_failed(kind),
            Ok(Event::RequestFailed {
                request_id: id,
                reason: RequestError::OpenFailed,
            })
        );
        let id = open_justification(&mut c);
        assert_eq!(
            c.cancel_request(id, RequestError::Cancelled).unwrap(),
            (
                Some(2),
                Event::RequestFailed {
                    request_id: id,
                    reason: RequestError::Cancelled,
                }
            )
        );
        assert_eq!(c.substream_reset(2, RequestError::Rejected), None);
    }
}

#[test]
fn ce128_sequences_bind_every_link_count_and_reject_whole_malformed_response() {
    let p = params();
    let first = block();
    let mut second = first.clone();
    second.header.parent = first.header.hash(&p);
    second.header.slot += 1;
    let mut third = second.clone();
    third.header.parent = second.header.hash(&p);
    third.header.slot += 1;
    for direction in [
        Direction::AscendingExclusive,
        Direction::DescendingInclusive,
    ] {
        let blocks = if direction == Direction::AscendingExclusive {
            vec![first.clone(), second.clone(), third.clone()]
        } else {
            vec![third.clone(), second.clone(), first.clone()]
        };
        let request_hash = if direction == Direction::AscendingExclusive {
            first.header.parent
        } else {
            third.header.hash(&p)
        };
        for scenario in 0..5 {
            let mut c = connection();
            open_up(&mut c);
            let id = open_ce(
                &mut c,
                BlockRequest {
                    hash: request_hash,
                    direction: direction.clone(),
                    max_blocks: if scenario == 1 { 2 } else { 3 },
                },
            );
            drain(&mut c, 2, 42);
            let mut wire_blocks = blocks.clone();
            if scenario == 2 {
                wire_blocks[1].header.parent = [99; 32];
            }
            let mut payload: Vec<_> = wire_blocks.iter().flat_map(|b| b.encode(&p)).collect();
            if scenario == 3 {
                payload.pop();
            }
            if scenario == 4 {
                payload.truncate(blocks[0].encode(&p).len());
            }
            let event = c.read_write(2, &frame(&payload), true, &mut []).event;
            match scenario {
                0 => assert_eq!(
                    event,
                    Some(Event::BlockResponse {
                        request_id: id,
                        blocks: blocks.clone()
                    })
                ),
                1 => assert_eq!(
                    event,
                    Some(Event::ProtocolError(ProtocolError::Decode(
                        DecodeError::LengthLimit
                    )))
                ),
                2 => assert_eq!(
                    event,
                    Some(Event::ProtocolError(ProtocolError::ResponseMismatch))
                ),
                3 => assert_eq!(
                    event,
                    Some(Event::ProtocolError(ProtocolError::Decode(
                        DecodeError::UnexpectedEnd
                    )))
                ),
                4 => assert_eq!(
                    event,
                    Some(Event::BlockResponse {
                        request_id: id,
                        blocks: vec![blocks[0].clone()]
                    })
                ),
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn ce128_no_data_reset_keeps_connection_and_proof_reservation() {
    let mut c = connection();
    open_up(&mut c);
    let block_id = open_ce(&mut c, request());
    let proof_id = c.request_justification([42; 32]).unwrap();
    assert_eq!(
        c.substream_reset(2, RequestError::Rejected),
        Some(Event::RequestFailed {
            request_id: block_id,
            reason: RequestError::Rejected
        })
    );
    assert_eq!(
        c.desired_outgoing_substreams(),
        Some(SubstreamKind::Ce130 {
            request_id: proof_id
        })
    );
    assert!(c.request_blocks(request()).is_ok());
}

fn captured_connection(capture: &Ce128) -> Connection {
    let mut c = Connection::new(
        capture.params.clone(),
        handshake(),
        Limits {
            max_message_size: capture.wire.len(),
            max_body_bytes: capture.wire.len(),
            ..limits()
        },
    )
    .unwrap();
    open_up(&mut c);
    c
}

fn captured_request(c: &mut Connection, request_frame: &[u8]) -> RequestId {
    let id = open_ce(c, BlockRequest::decode(&request_frame[4..]).unwrap());
    assert_eq!(drain(c, 2, 7), ([&[128], request_frame].concat(), true));
    id
}

#[rstest]
fn captured_ce128_sequence_waits_for_fin(captured_ce128: Ce128) {
    let capture = captured_ce128;
    let mut c = captured_connection(&capture);
    let id = captured_request(&mut c, &capture.request_frame);
    // No header may escape before the entire fragmented sequence and FIN arrive.
    assert!(feed(&mut c, 2, &capture.wire, 7).is_empty());
    let Some(Event::BlockResponse { request_id, blocks }) =
        c.read_write(2, &[], true, &mut []).event
    else {
        panic!("captured sequence did not complete on FIN");
    };
    assert_eq!(request_id, id);
    assert_eq!(blocks.len(), capture.blocks.len());
    for (block, expected) in blocks.iter().zip(&capture.blocks) {
        assert_eq!(
            hex::encode(block.header.hash(&capture.params)),
            expected.header_hash
        );
    }
}

#[rstest]
fn captured_ce128_rejects_broken_parent_links(
    captured_ce128: Ce128,
    #[values(0, 1, 2, 3, 4)] block: usize,
) {
    let capture = captured_ce128;
    let mut c = captured_connection(&capture);
    captured_request(&mut c, &capture.request_frame);
    let mut bad = capture.wire.clone();
    bad[4 + capture.blocks[block].start] ^= 1;
    assert_eq!(
        c.read_write(2, &bad, true, &mut []).event,
        Some(Event::ProtocolError(ProtocolError::ResponseMismatch))
    );
}

#[rstest]
#[case::truncated(Corruption::Truncated, DecodeError::UnexpectedEnd)]
#[case::too_many_tickets(Corruption::TooManyTickets, DecodeError::LengthLimit)]
fn captured_ce128_rejects_malformed_extrinsics_atomically(
    captured_ce128: Ce128,
    #[values(0, 1, 2, 3, 4)] block: usize,
    #[case] corruption: Corruption,
    #[case] expected: DecodeError,
) {
    let capture = captured_ce128;
    let mut c = captured_connection(&capture);
    captured_request(&mut c, &capture.request_frame);
    let payload = capture.corrupted_payload(block, corruption);
    assert_eq!(
        c.read_write(2, &frame(&payload), true, &mut []).event,
        Some(Event::ProtocolError(ProtocolError::Decode(expected)))
    );
}

#[rstest]
#[case::unknown_hash("unknown-hash")]
#[case::tip("tip-no-data")]
fn captured_ce128_no_data_resets_leave_connection_usable(
    captured_ce128: Ce128,
    #[case] name: &str,
) {
    let capture = captured_ce128;
    let reset = capture
        .resets
        .iter()
        .find(|reset| reset.name == name)
        .unwrap();
    assert!(reset.reset);
    assert_eq!(reset.source, "stream");
    assert_eq!(reset.stream_error_code, 6);
    assert!(reset.response_frame_hex.is_none());
    let mut c = captured_connection(&capture);
    let id = captured_request(&mut c, &reset.request_frame);
    // WebTransport surfaces RESET_STREAM out of band; there are no CE128 bytes.
    assert_eq!(
        c.substream_reset(2, RequestError::Rejected),
        Some(Event::RequestFailed {
            request_id: id,
            reason: RequestError::Rejected
        })
    );
    assert_eq!(c.substream_reset(2, RequestError::Rejected), None);
    assert_eq!(c.streams.len(), 1); // UP0 survives.
    let next = captured_request(&mut c, &capture.request_frame);
    assert_ne!(id, next);
    assert!(
        matches!(c.read_write(2, &capture.wire, true, &mut []).event,
        Some(Event::BlockResponse { request_id, blocks }) if request_id == next && blocks.len() == capture.blocks.len())
    );
}
