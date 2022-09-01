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

//! Implementation of a WebSocket client that wraps around an abstract representation of a TCP
//! socket through the `AsyncRead` and `AsyncWrite` traits.

#![cfg(all(feature = "std"))]
#![cfg_attr(docsrs, doc(cfg(all(feature = "std"))))]

use futures::prelude::*;

use core::{
    cmp, mem,
    pin::Pin,
    task::{Context, Poll},
};

use std::io;

/// Configuration for [`websocket_client_handshake`].
pub struct Config<'a, T> {
    /// Socket to negotiate WebSocket on top of.
    pub tcp_socket: T,

    /// Values to pass for the `Host` HTTP header. Example values include `example.com:1234` or
    /// `127.0.0.1:3337`.
    pub host: &'a str,

    /// URL to pass to the server during the HTTP handshake. Typically `/`.
    pub url: &'a str,
}

/// Negotiates the WebSocket protocol (including the HTTP-like request) on the given socket, and
/// returns an object that translates reads and writes into WebSocket binary frames.
pub async fn websocket_client_handshake<'a, T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    config: Config<'a, T>,
) -> Result<Connection<T>, io::Error> {
    let mut client = soketto::handshake::Client::new(config.tcp_socket, config.host, config.url);

    let (sender, receiver) = match client.handshake().await {
        Ok(soketto::handshake::ServerResponse::Accepted { .. }) => client.into_builder().finish(),
        Ok(soketto::handshake::ServerResponse::Redirect { .. }) => {
            // TODO: implement?
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Redirections not implemented",
            ));
        }
        Ok(soketto::handshake::ServerResponse::Rejected { status_code }) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Status code {}", status_code),
            ))
        }
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
    };

    Ok(Connection {
        sender: Write::Idle(sender),
        receiver: Read::Idle(receiver, Vec::with_capacity(1024), 0),
    })
}

/// Negotiated WebSocket connection.
///
/// Implements the `AsyncRead` and `AsyncWrite` traits.
pub struct Connection<T> {
    sender: Write<T>,
    receiver: Read<T>,
}

enum Read<T> {
    Idle(soketto::connection::Receiver<T>, Vec<u8>, usize),
    Error(soketto::connection::Error),
    InProgress(
        future::BoxFuture<
            'static,
            Result<(soketto::connection::Receiver<T>, Vec<u8>), soketto::connection::Error>,
        >,
    ),
    Poisoned,
}

enum Write<T> {
    Idle(soketto::connection::Sender<T>),
    Writing(
        future::BoxFuture<
            'static,
            Result<soketto::connection::Sender<T>, soketto::connection::Error>,
        >,
    ),
    Flushing(
        future::BoxFuture<
            'static,
            Result<soketto::connection::Sender<T>, soketto::connection::Error>,
        >,
    ),
    Closing(future::BoxFuture<'static, Result<(), soketto::connection::Error>>),
    Closed,
    Error(soketto::connection::Error),
    Poisoned,
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncRead for Connection<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        assert_ne!(out_buf.len(), 0);

        loop {
            match mem::replace(&mut self.receiver, Read::Poisoned) {
                Read::Idle(socket, pending, pending_pos) if pending_pos < pending.len() => {
                    let to_copy = cmp::min(out_buf.len(), pending.len() - pending_pos);
                    debug_assert_ne!(to_copy, 0);
                    out_buf[..to_copy].copy_from_slice(&pending[pending_pos..][..to_copy]);
                    self.receiver = Read::Idle(socket, pending, pending_pos + to_copy);
                    return Poll::Ready(Ok(to_copy));
                }
                Read::Idle(mut socket, mut buffer, _) => {
                    buffer.clear();
                    self.receiver = Read::InProgress(Box::pin(async move {
                        socket.receive_data(&mut buffer).await?;
                        Ok((socket, buffer))
                    }));
                }
                Read::InProgress(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.receiver = Read::InProgress(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok((socket, buffer))) => {
                        self.receiver = Read::Idle(socket, buffer, 0);
                    }
                    Poll::Ready(Err(err)) => {
                        self.receiver = Read::Error(err);
                    }
                },
                Read::Error(err) => {
                    let out_err = convert_err(&err);
                    self.receiver = Read::Error(err);
                    return Poll::Ready(Err(out_err));
                }
                Read::Poisoned => unreachable!(),
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncWrite for Connection<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match mem::replace(&mut self.sender, Write::Poisoned) {
                Write::Idle(mut socket) => {
                    let len = buf.len();
                    let buf = buf.to_vec();
                    self.sender = Write::Writing(Box::pin(async move {
                        socket.send_binary_mut(buf).await?;
                        Ok(socket)
                    }));
                    return Poll::Ready(Ok(len));
                }
                Write::Flushing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Flushing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Writing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Writing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Closing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(())) => {
                        self.sender = Write::Closed;
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closed => return Poll::Ready(Ok(0)), // TODO: is this correct?
                Write::Error(err) => {
                    let out_err = convert_err(&err);
                    self.sender = Write::Error(err);
                    return Poll::Ready(Err(out_err));
                }
                Write::Poisoned => unreachable!(),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match mem::replace(&mut self.sender, Write::Poisoned) {
                Write::Idle(mut socket) => {
                    self.sender = Write::Flushing(Box::pin(async move {
                        socket.flush().await?;
                        Ok(socket)
                    }));
                }
                Write::Flushing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Flushing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Writing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Writing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Closing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(())) => {
                        self.sender = Write::Closed;
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closed => return Poll::Ready(Ok(())),
                Write::Error(err) => {
                    let out_err = convert_err(&err);
                    self.sender = Write::Error(err);
                    return Poll::Ready(Err(out_err));
                }
                Write::Poisoned => unreachable!(),
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match mem::replace(&mut self.sender, Write::Poisoned) {
                Write::Idle(mut socket) => {
                    self.sender = Write::Closing(Box::pin(async move {
                        socket.close().await?;
                        Ok(())
                    }));
                }
                Write::Flushing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Flushing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Writing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Writing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(socket)) => {
                        self.sender = Write::Idle(socket);
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closing(mut future) => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        self.sender = Write::Closing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(())) => {
                        self.sender = Write::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => {
                        self.sender = Write::Error(err);
                    }
                },
                Write::Closed => return Poll::Ready(Ok(())),
                Write::Error(err) => {
                    let out_err = convert_err(&err);
                    self.sender = Write::Error(err);
                    return Poll::Ready(Err(out_err));
                }
                Write::Poisoned => unreachable!(),
            }
        }
    }
}

fn convert_err(err: &soketto::connection::Error) -> io::Error {
    match err {
        soketto::connection::Error::Io(err) => io::Error::new(err.kind(), err.to_string()),
        soketto::connection::Error::Codec(err) => {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        }
        soketto::connection::Error::Extension(err) => {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        }
        soketto::connection::Error::UnexpectedOpCode(err) => {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        }
        soketto::connection::Error::Utf8(err) => {
            io::Error::new(io::ErrorKind::InvalidData, err.to_string())
        }
        soketto::connection::Error::MessageTooLarge { .. } => {
            io::Error::from(io::ErrorKind::InvalidData)
        }
        soketto::connection::Error::Closed => io::Error::from(io::ErrorKind::ConnectionAborted),
        _ => io::Error::from(io::ErrorKind::Other),
    }
}

#[cfg(test)]
mod tests {
    use futures::prelude::*;

    #[test]
    fn is_send() {
        // Makes sure at compilate time that `Connection` implements `Send`.
        fn req_send<T: Send>() {}
        #[allow(unused)]
        fn trait_bounds<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>() {
            req_send::<super::Connection<T>>()
        }
    }
}
