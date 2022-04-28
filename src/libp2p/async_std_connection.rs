// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

#![cfg(feature = "std")]
#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

// TODO: usage and example

use super::collection::ReadWrite;
use core::{fmt, ops, pin::Pin};
use futures::prelude::*;
use std::io;

pub mod with_buffers;

/// Outcome of processing the connection task.
#[derive(Debug)]
pub enum RunOutcome<TNow> {
    /// Data is ready on the socket.
    Ready(ConnectionTask<TNow>),

    /// In order to continue, connection task needs a future that becomes ready at a specific
    /// moment.
    TimerNeeded(TimerNeeded<TNow>),

    /// Connection task has ended because an I/O error has happened on the socket.
    IoError(io::Error),
}

/// Access to a [`ReadWrite`] within a [`ConnectionTask`].
///
/// This struct dereferences to [`ReadWrite`].
pub struct ReadWriteLock<'a, TNow> {
    inner: ReadWrite<'a, TNow>,
    latest_read_outcome: &'a mut ReadWriteOutcome<TNow>,
}

impl<'a, TNow> ops::Deref for ReadWriteLock<'a, TNow> {
    type Target = ReadWrite<'a, TNow>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, TNow> ops::DerefMut for ReadWriteLock<'a, TNow> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, TNow> fmt::Debug for ReadWriteLock<'a, TNow>
where
    ReadWrite<'a, TNow>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(ops::Deref::deref(self), f)
    }
}

impl<'a, TNow> Drop for ReadWriteLock<'a, TNow> {
    fn drop(&mut self) {
        self.latest_read_outcome.read_bytes = self.inner.read_bytes;
        self.latest_read_outcome.written_bytes = self.inner.written_bytes;
        self.latest_read_outcome.write_closed = self.inner.outgoing_buffer.is_none();
        self.latest_read_outcome.wake_up_after = self.inner.wake_up_after.take();
        self.latest_read_outcome.wake_up_future = self.inner.wake_up_future.take();
    }
}

/// Active connection task with data potentially ready.
pub struct ConnectionTask<TNow> {
    tcp_socket: with_buffers::WithBuffers<async_std::net::TcpStream>,
    latest_read_outcome: ReadWriteOutcome<TNow>,
}

impl<TNow> ConnectionTask<TNow> {
    /// Initializes a new [`ConnectionTask`] encapsulating the given socket.
    ///
    /// The socket must have its writing side still open.
    pub fn new(tcp_socket: async_std::net::TcpStream) -> Self {
        // The Nagle algorithm, implemented in the kernel, consists in buffering the data to be
        // sent out and waiting a bit before actually sending it out, in order to potentially merge
        // multiple writes in a row into one packet. In the implementation below, it is guaranteed
        // that the buffer in `WithBuffers` is filled with as much data as possible before the
        // operating system gets involved. As such, we disable the Nagle algorithm, in order to
        // avoid adding an artificial delay to all sends.
        let _ = tcp_socket.set_nodelay(true);

        // The socket is wrapped around a `WithBuffers` object containing a read buffer and a write
        // buffer. These are the buffers whose pointer is passed to `read(2)` and `write(2)` when
        // reading/writing the socket.
        let tcp_socket = with_buffers::WithBuffers::new(tcp_socket);

        ConnectionTask {
            tcp_socket,
            latest_read_outcome: ReadWriteOutcome {
                read_bytes: 0,
                written_bytes: 0,
                write_closed: false,
                wake_up_after: None,
                wake_up_future: None,
            },
        }
    }

    /// Gives access to a [`ReadWrite`] pointing to the internals of the connection task. This
    /// [`ReadWrite`] can be passed to networking-related functions in order to synchronize a
    /// network state machine with the actual socket.
    pub fn read_write(&mut self, now: TNow) -> ReadWriteLock<TNow> {
        let (read_buffer, write_buffer) = self.tcp_socket.buffers().unwrap();

        ReadWriteLock {
            inner: ReadWrite {
                now,
                incoming_buffer: read_buffer.map(|b| b.0),
                outgoing_buffer: write_buffer,
                read_bytes: self.latest_read_outcome.read_bytes,
                written_bytes: self.latest_read_outcome.written_bytes,
                wake_up_after: self.latest_read_outcome.wake_up_after.take(),
                wake_up_future: self.latest_read_outcome.wake_up_future.take(),
            },
            latest_read_outcome: &mut self.latest_read_outcome,
        }
    }

    /// After calling [`ConnectionTask::read_write`] and updating the [`ReadWrite`], call this
    /// function to synchronize the buffers with the actual socket.
    ///
    /// This function returns when the connection task needs something or when data is ready on
    /// the socket.
    pub async fn resume(mut self) -> RunOutcome<TNow> {
        let wake_up_future =
            if let Some(wake_up_future) = self.latest_read_outcome.wake_up_future.take() {
                future::Either::Left(wake_up_future)
            } else {
                future::Either::Right(future::pending())
            }
            .boxed();

        if self.latest_read_outcome.write_closed && !self.tcp_socket.is_closed() {
            self.tcp_socket.close();
        }

        self.tcp_socket.advance(
            self.latest_read_outcome.read_bytes,
            self.latest_read_outcome.written_bytes,
        );

        let immediately_resume =
            self.latest_read_outcome.read_bytes != 0 || self.latest_read_outcome.written_bytes != 0;

        self.latest_read_outcome.read_bytes = 0;
        self.latest_read_outcome.written_bytes = 0;
        let wake_up = self.latest_read_outcome.wake_up_after.take();

        if immediately_resume {
            return RunOutcome::Ready(self);
        }

        if let Some(wake_up) = wake_up {
            RunOutcome::TimerNeeded(TimerNeeded {
                inner: self,
                wake_up_future,
                when_wake_up: wake_up,
            })
        } else {
            self.continue_with_timer(wake_up_future, future::pending())
                .await
        }
    }

    async fn continue_with_timer(
        mut self,
        wake_up_future: future::BoxFuture<'static, ()>,
        poll_after: impl Future<Output = ()>,
    ) -> RunOutcome<TNow> {
        let poll_after = poll_after.fuse();

        futures::pin_mut!(poll_after);
        let mut tcp_socket = Pin::new(&mut self.tcp_socket);
        futures::select! {
            _ = tcp_socket.as_mut().process().fuse() => {},
            _ = wake_up_future.fuse() => {},
            () = poll_after => {
                // Nothing to do, but guarantees that we loop again.
            }
        }

        if let Err(err) = self.tcp_socket.buffers() {
            return RunOutcome::IoError(io::Error::new(err.kind(), err.to_string()));
        }

        RunOutcome::Ready(self)
    }
}

impl<TNow> fmt::Debug for ConnectionTask<TNow> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ConnectionTask").finish()
    }
}

struct ReadWriteOutcome<TNow> {
    read_bytes: usize,
    written_bytes: usize,
    write_closed: bool,
    wake_up_after: Option<TNow>,
    wake_up_future: Option<future::BoxFuture<'static, ()>>,
}

/// In order to continue, connection task needs a future that becomes ready at a specific moment.
pub struct TimerNeeded<TNow> {
    inner: ConnectionTask<TNow>,
    wake_up_future: future::BoxFuture<'static, ()>,
    when_wake_up: TNow,
}

impl<TNow> TimerNeeded<TNow> {
    /// Returns the moment when the timer to pass to [`TimerNeeded::resume`] must become ready.
    ///
    /// > **Note**: Be aware that this might be in the past.
    pub fn when(&self) -> &TNow {
        &self.when_wake_up
    }

    /// Resumes the connection task, using the timer passed as parameter. The timer passed as
    /// parameter must become ready at the moment returned by [`TimerNeeded::when`].
    pub async fn resume(self, delay: impl Future<Output = ()>) -> RunOutcome<TNow> {
        self.inner
            .continue_with_timer(self.wake_up_future, delay)
            .await
    }
}

impl<TNow> fmt::Debug for TimerNeeded<TNow> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TimerNeeded").finish()
    }
}
