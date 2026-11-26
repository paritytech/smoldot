// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

#![cfg(test)]

use super::{Config, DeadSubstreamTy, ReadWriteOutcome, Yamux};
use crate::libp2p::read_write::ReadWrite;
use alloc::{vec, vec::Vec};
use core::{num::NonZero, time::Duration};

const SYN: u16 = 0x1;
const FIN: u16 = 0x4;
const RST: u16 = 0x8;

fn new_yamux() -> Yamux<Duration, ()> {
    Yamux::new(Config {
        is_initiator: false,
        capacity: 0,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZero::<u32>::new(8192).unwrap(),
        max_simultaneous_queued_pongs: NonZero::<usize>::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZero::<usize>::new(1024).unwrap(),
    })
}

fn frame(ty: u8, flags: u16, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0, ty];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Feeds `incoming` to `yamux` and runs it until idle. Accepts incoming substreams and calls
/// `on_substream` every time a substream is processed. Never removes dead substreams.
fn run(
    mut yamux: Yamux<Duration, ()>,
    incoming: Vec<u8>,
    on_substream: &mut dyn FnMut(&mut ReadWrite<Duration>),
) -> Yamux<Duration, ()> {
    let mut rw = ReadWrite {
        now: Duration::ZERO,
        incoming_buffer: incoming,
        expected_incoming_bytes: Some(0),
        read_bytes: 0,
        write_buffers: Vec::new(),
        write_bytes_queued: 0,
        write_bytes_queueable: Some(1 << 20),
        wake_up_after: None,
    };
    for _ in 0..100 {
        rw.wake_up_after = None;
        let (next, idle) = match yamux.read_write(&mut rw).unwrap() {
            ReadWriteOutcome::Idle { yamux } => (yamux, true),
            ReadWriteOutcome::IncomingSubstream { mut yamux } => {
                let id = yamux.accept_pending_substream(()).unwrap();
                yamux.mark_substream_write_ready(id);
                (yamux, false)
            }
            ReadWriteOutcome::ProcessSubstream {
                mut substream_read_write,
            } => {
                on_substream(substream_read_write.read_write());
                (substream_read_write.finish(), false)
            }
            ReadWriteOutcome::StreamReset { yamux, .. } => (yamux, false),
            ReadWriteOutcome::GoAway { yamux, .. } => (yamux, false),
            ReadWriteOutcome::PingResponse { yamux } => (yamux, false),
        };
        yamux = next;
        if idle && rw.wake_up_after.is_none() {
            return yamux;
        }
    }
    panic!("yamux didn't become idle")
}

/// Substream behaviour that closes its writing side.
fn close_write(rw: &mut ReadWrite<Duration>) {
    rw.write_bytes_queueable = None;
}

/// Substream behaviour that reads one byte at a time, the way a length prefix is read, and
/// records the bytes read and how many there were when the reading side was found closed.
fn read_byte_by_byte<'a>(
    got: &'a mut Vec<u8>,
    closed_after: &'a mut Option<usize>,
) -> impl FnMut(&mut ReadWrite<Duration>) + 'a {
    move |rw| loop {
        match rw.incoming_bytes_take(1) {
            Ok(Some(byte)) => got.extend(byte),
            Ok(None) => break,
            Err(_) => {
                closed_after.get_or_insert(got.len());
                break;
            }
        }
    }
}

/// A substream closed by both sides is dead until the user removes it. A RST from the remote
/// for it in the meantime must not be treated as a new death.
#[test]
fn rst_on_closed_substream_not_yet_removed() {
    // Remote opens stream 1 and closes its writing side. We close ours.
    let yamux = run(new_yamux(), frame(0, SYN | FIN, 1, &[]), &mut close_write);
    assert_eq!(yamux.dead_substreams().count(), 1);

    // Remote resets stream 1 before the dead substream was removed.
    let yamux = run(yamux, frame(1, RST, 1, &[]), &mut close_write);
    let dead = yamux.dead_substreams().collect::<Vec<_>>();
    assert_eq!(dead.len(), 1);
    assert!(matches!(dead[0].1, DeadSubstreamTy::ClosedGracefully));
}

/// The data of a frame with the FIN flag is all read before the reading side is closed, even
/// when the substream asks for fewer bytes than the frame holds.
#[test]
fn data_with_fin_is_read_before_close() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let (mut got, mut closed_after) = (Vec::new(), None);
    let mut reader = read_byte_by_byte(&mut got, &mut closed_after);

    let yamux = run(new_yamux(), frame(0, SYN, 1, &[]), &mut reader);
    let _ = run(yamux, frame(0, FIN, 1, &data), &mut reader);
    drop(reader);

    assert_eq!(got, data);
    assert_eq!(closed_after, Some(data.len()));
}

/// Same as [`data_with_fin_is_read_before_close`], for a frame that also opens the substream.
#[test]
fn data_with_syn_and_fin_is_read_before_close() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let (mut got, mut closed_after) = (Vec::new(), None);
    let mut reader = read_byte_by_byte(&mut got, &mut closed_after);

    let _ = run(new_yamux(), frame(0, SYN | FIN, 1, &data), &mut reader);
    drop(reader);

    assert_eq!(got, data);
    assert_eq!(closed_after, Some(data.len()));
}
