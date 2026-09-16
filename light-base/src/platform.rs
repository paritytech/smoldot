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

use alloc::borrow::Cow;
use core::{fmt, net::IpAddr, ops, panic::UnwindSafe, pin::Pin, str, time::Duration};

pub use smoldot::libp2p::read_write;

#[cfg(feature = "std")]
pub use smoldot::libp2p::with_buffers;

// TODO: this module should probably not be public?
pub mod address_parse;
pub mod default;

mod with_prefix;

#[cfg(feature = "std")]
pub use default::DefaultPlatform;

pub use with_prefix::WithPrefix;

/// Access to a platform's capabilities.
///
/// Implementations of this trait are expected to be cheaply-clonable "handles". All clones of the
/// same platform share the same objects. For instance, it is legal to create clone a platform,
/// then create a connection on one clone, then access this connection on the other clone.
pub trait PlatformRef: UnwindSafe + Clone + Send + Sync + 'static {
    /// `Future` that resolves once a certain amount of time has passed or a certain point in time
    /// is reached. See [`PlatformRef::sleep`] and [`PlatformRef::sleep_until`].
    type Delay: Future<Output = ()> + Send + 'static;

    /// A certain point in time. Typically `std::time::Instant`, but one can also
    /// use `core::time::Duration`.
    ///
    /// The implementations of the `Add` and `Sub` traits must panic in case of overflow or
    /// underflow, similar to the ones of `std::time::Instant` and `core::time::Duration`.
    type Instant: Clone
        + ops::Add<Duration, Output = Self::Instant>
        + ops::Sub<Self::Instant, Output = Duration>
        + PartialOrd
        + Ord
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;

    /// A multi-stream connection.
    ///
    /// This object is merely a handle. The underlying connection should be dropped only after
    /// the `MultiStream` and all its associated substream objects ([`PlatformRef::Stream`]) have
    /// been dropped.
    type MultiStream: Send + Sync + 'static;

    /// Opaque object representing either a single-stream connection or a substream in a
    /// multi-stream connection.
    ///
    /// If this object is abruptly dropped, the underlying single stream connection or substream
    /// should be abruptly dropped (i.e. RST) as well, unless its reading and writing sides
    /// have been gracefully closed in the past.
    type Stream: Send + 'static;

    /// Object that dereferences to [`read_write::ReadWrite`] and gives access to the stream's
    /// buffers. See the [`read_write`] module for more information.
    /// See also [`PlatformRef::read_write_access`].
    type ReadWriteAccess<'a>: ops::DerefMut<Target = read_write::ReadWrite<Self::Instant>> + 'a;

    /// Reference to an error that happened on a stream.
    ///
    /// Potentially returned by [`PlatformRef::read_write_access`].
    ///
    /// Typically `&'a std::io::Error`.
    type StreamErrorRef<'a>: fmt::Display + fmt::Debug;

    /// `Future` returned by [`PlatformRef::connect_stream`].
    type StreamConnectFuture: Future<Output = Self::Stream> + Send + 'static;
    /// `Future` returned by [`PlatformRef::connect_multistream`].
    type MultiStreamConnectFuture: Future<Output = MultiStreamWebRtcConnection<Self::MultiStream>>
        + Send
        + 'static;
    /// `Future` returned by [`PlatformRef::wait_read_write_again`].
    type StreamUpdateFuture<'a>: Future<Output = ()> + Send + 'a;
    /// `Future` returned by [`PlatformRef::next_substream`].
    type NextSubstreamFuture<'a>: Future<Output = Option<(Self::Stream, SubstreamDirection)>>
        + Send
        + 'a;

    /// Returns the time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time)
    /// (i.e. 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    ///
    /// # Panic
    ///
    /// Panics if the system time is configured to be below the UNIX epoch. This situation is a
    /// very very niche edge case that isn't worth handling.
    ///
    fn now_from_unix_epoch(&self) -> Duration;

    /// Returns an object that represents "now".
    fn now(&self) -> Self::Instant;

    /// The given buffer must be completely filled with pseudo-random bytes.
    ///
    /// # Panic
    ///
    /// Must panic if for some reason it is not possible to fill the buffer.
    ///
    fn fill_random_bytes(&self, buffer: &mut [u8]);

    /// Creates a future that becomes ready after at least the given duration has elapsed.
    fn sleep(&self, duration: Duration) -> Self::Delay;

    /// Creates a future that becomes ready after the given instant has been reached.
    fn sleep_until(&self, when: Self::Instant) -> Self::Delay;

    /// Spawns a task that runs indefinitely in the background.
    ///
    /// The first parameter is the name of the task, which can be useful for debugging purposes.
    ///
    /// The `Future` must be run until it yields a value.
    ///
    /// Implementers should be aware of the fact that polling the `Future` might panic (never
    /// intentionally, but in case of a bug). Many tasks can be restarted if they panic, and
    /// implementers are encouraged to absorb the panics that happen when polling. If a panic
    /// happens, the `Future` that has panicked must never be polled again.
    ///
    /// > **Note**: Ideally, the `task` parameter would require the `UnwindSafe` trait.
    /// >           Unfortunately, at the time of writing of this comment, it is extremely
    /// >           difficult if not impossible to implement this trait on `Future`s. It is for
    /// >           the same reason that the `std::thread::spawn` function of the standard library
    /// >           doesn't require its parameter to implement `UnwindSafe`.
    fn spawn_task(&self, task_name: Cow<str>, task: impl Future<Output = ()> + Send + 'static);

    /// Emit a log line.
    ///
    /// The `log_level` and `log_target` can be used in order to filter desired log lines.
    ///
    /// The `message` is typically a short constant message indicating the nature of the log line.
    /// The `key_values` are a list of keys and values that are the parameters of the log message.
    ///
    /// For example, `message` can be `"block-announce-received"` and `key_values` can contain
    /// the entries `("block_hash", ...)` and `("sender", ...)`.
    ///
    /// At the time of writing of this comment, `message` can also be a message written in plain
    /// english and destined to the user of the library. This might disappear in the future.
    // TODO: act on this last sentence ^
    fn log<'a>(
        &self,
        log_level: LogLevel,
        log_target: &'a str,
        message: &'a str,
        key_values: impl Iterator<Item = (&'a str, &'a dyn fmt::Display)>,
    );

    /// Value returned when a JSON-RPC client requests the name of the client, or when a peer
    /// performs an identification request. Reasonable value is `env!("CARGO_PKG_NAME")`.
    fn client_name(&'_ self) -> Cow<'_, str>;

    /// Value returned when a JSON-RPC client requests the version of the client, or when a peer
    /// performs an identification request. Reasonable value is `env!("CARGO_PKG_VERSION")`.
    fn client_version(&'_ self) -> Cow<'_, str>;

    /// Returns `true` if [`PlatformRef::connect_stream`] or [`PlatformRef::connect_multistream`]
    /// accepts a connection of the corresponding type.
    ///
    /// > **Note**: This function is meant to be pure. Implementations are expected to always
    /// >           return the same value for the same [`ConnectionType`] input. Enabling or
    /// >           disabling certain connection types after start-up is not supported.
    fn supports_connection_type(&self, connection_type: ConnectionType) -> bool;

    /// Starts a connection attempt to the given address.
    ///
    /// This function is only ever called with an `address` of a type for which
    /// [`PlatformRef::supports_connection_type`] returned `true` in the past.
    ///
    /// This function returns a `Future`. This `Future` **must** return as soon as possible, and
    /// must **not** wait for the connection to be established.
    /// In most scenarios, the `Future` returned by this function should immediately produce
    /// an output.
    ///
    /// # Panic
    ///
    /// The function implementation panics if [`Address`] is of a type for which
    /// [`PlatformRef::supports_connection_type`] returns `false`.
    ///
    fn connect_stream(&self, address: Address) -> Self::StreamConnectFuture;

    /// Starts a connection attempt to the given address.
    ///
    /// This function is only ever called with an `address` of a type for which
    /// [`PlatformRef::supports_connection_type`] returned `true` in the past.
    ///
    /// > **Note**: A so-called "multistream connection" is a connection made of multiple
    /// >           substreams, and for which the opening and closing or substreams is handled by
    /// >           the environment rather than by smoldot itself. Most platforms do not need to
    /// >           support multistream connections. This function is in practice used in order
    /// >           to support WebRTC connections when embedding smoldot-light within a web
    /// >           browser.
    ///
    /// This function returns a `Future`. This `Future` **must** return as soon as possible, and
    /// must **not** wait for the connection to be established.
    /// In most scenarios, the `Future` returned by this function should immediately produce
    /// an output.
    ///
    /// # Panic
    ///
    /// The function implementation panics if [`MultiStreamAddress`] is of a type for which
    /// [`PlatformRef::supports_connection_type`] returns `false`.
    ///
    fn connect_multistream(&self, address: MultiStreamAddress) -> Self::MultiStreamConnectFuture;

    /// Queues the opening of an additional outbound substream.
    ///
    /// The substream, once opened, must be yielded by [`PlatformRef::next_substream`].
    ///
    /// Calls to this function should be ignored if the connection has already been killed by the
    /// remote.
    ///
    /// > **Note**: No mechanism exists in this API to handle the situation where a substream fails
    /// >           to open, as this is not supposed to happen. If you need to handle such a
    /// >           situation, either try again opening a substream again or reset the entire
    /// >           connection.
    fn open_out_substream(&self, connection: &mut Self::MultiStream);

    /// Waits until a new incoming substream arrives on the connection.
    ///
    /// This returns both inbound and outbound substreams. Outbound substreams should only be
    /// yielded once for every call to [`PlatformRef::open_out_substream`].
    ///
    /// The future can also return `None` if the connection has been killed by the remote. If
    /// the future returns `None`, the user of the `PlatformRef` should drop the `MultiStream` and
    /// all its associated `Stream`s as soon as possible.
    fn next_substream<'a>(
        &self,
        connection: &'a mut Self::MultiStream,
    ) -> Self::NextSubstreamFuture<'a>;

    /// Returns an object that implements `DerefMut<Target = ReadWrite>`. The
    /// [`read_write::ReadWrite`] object allows the API user to read data from the stream and write
    /// data to the stream.
    ///
    /// If the stream has been reset in the past, this function should return a reference to
    /// the error that happened.
    ///
    /// See the documentation of [`read_write`] for more information
    ///
    /// > **Note**: The `with_buffers` module provides a helper to more easily implement this
    /// >           function.
    fn read_write_access<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Result<Self::ReadWriteAccess<'a>, Self::StreamErrorRef<'a>>;

    /// Returns a future that becomes ready when [`PlatformRef::read_write_access`] should be
    /// called again on this stream.
    ///
    /// Must always returned immediately if [`PlatformRef::read_write_access`] has never been
    /// called on this stream.
    ///
    /// See the documentation of [`read_write`] for more information.
    ///
    /// > **Note**: The `with_buffers` module provides a helper to more easily implement this
    /// >           function.
    fn wait_read_write_again<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Self::StreamUpdateFuture<'a>;
}

/// Log level of a log entry.
///
/// See [`PlatformRef::log`].
#[derive(Debug)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

/// Established multistream connection information. See [`PlatformRef::connect_multistream`].
#[derive(Debug)]
pub struct MultiStreamWebRtcConnection<TConnection> {
    /// Object representing the WebRTC or WebTransport connection.
    pub connection: TConnection,
    /// SHA256 hash of the TLS certificate used by the local node at the DTLS layer.
    /// Zero for WebTransport, which does not use a local DTLS certificate.
    pub local_tls_certificate_sha256: [u8; 32],
}

/// Direction in which a substream has been opened. See [`PlatformRef::next_substream`].
#[derive(Debug)]
pub enum SubstreamDirection {
    /// Substream has been opened by the remote.
    Inbound,
    /// Substream has been opened locally in response to [`PlatformRef::open_out_substream`].
    Outbound,
}

/// Connection type passed to [`PlatformRef::supports_connection_type`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// TCP/IP connection.
    TcpIpv4,
    /// TCP/IP connection.
    TcpIpv6,
    /// TCP/IP connection.
    TcpDns,
    /// Non-secure WebSocket connection.
    WebSocketIpv4 {
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// Non-secure WebSocket connection.
    WebSocketIpv6 {
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// WebSocket connection.
    WebSocketDns {
        /// `true` for WebSocket secure connections.
        secure: bool,
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// Libp2p-specific WebRTC flavour.
    WebRtcIpv4,
    /// Libp2p-specific WebRTC flavour.
    WebRtcIpv6,
    /// Raw WebTransport over HTTP/3, without a libp2p handshake or framing.
    WebTransportIpv4,
    /// Raw WebTransport over HTTP/3, without a libp2p handshake or framing.
    WebTransportIpv6,
}

impl<'a> From<&'a Address<'a>> for ConnectionType {
    fn from(address: &'a Address<'a>) -> ConnectionType {
        match address {
            Address::TcpIp {
                ip: IpAddr::V4(_), ..
            } => ConnectionType::TcpIpv4,
            Address::TcpIp {
                ip: IpAddr::V6(_), ..
            } => ConnectionType::TcpIpv6,
            Address::TcpDns { .. } => ConnectionType::TcpDns,
            Address::WebSocketIp {
                ip: IpAddr::V4(ip), ..
            } => ConnectionType::WebSocketIpv4 {
                remote_is_localhost: ip.is_loopback(),
            },
            Address::WebSocketIp {
                ip: IpAddr::V6(ip), ..
            } => ConnectionType::WebSocketIpv6 {
                remote_is_localhost: ip.is_loopback(),
            },
            Address::WebSocketDns {
                hostname, secure, ..
            } => ConnectionType::WebSocketDns {
                secure: *secure,
                remote_is_localhost: hostname.eq_ignore_ascii_case("localhost"),
            },
        }
    }
}

impl<'a> From<&'a MultiStreamAddress<'a>> for ConnectionType {
    fn from(address: &'a MultiStreamAddress) -> ConnectionType {
        match address {
            MultiStreamAddress::WebRtc {
                ip: IpAddr::V4(_), ..
            } => ConnectionType::WebRtcIpv4,
            MultiStreamAddress::WebRtc {
                ip: IpAddr::V6(_), ..
            } => ConnectionType::WebRtcIpv6,
            MultiStreamAddress::WebTransport {
                ip: IpAddr::V4(_), ..
            } => ConnectionType::WebTransportIpv4,
            MultiStreamAddress::WebTransport {
                ip: IpAddr::V6(_), ..
            } => ConnectionType::WebTransportIpv6,
        }
    }
}

/// Address passed to [`PlatformRef::connect_stream`].
// TODO: we don't differentiate between Dns4 and Dns6
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Address<'a> {
    /// TCP/IP connection with a domain name.
    TcpDns {
        /// DNS hostname to connect to.
        ///
        /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
        /// >           string. Any binary data can be used as a domain name, provided it follows
        /// >           a few restrictions (notably its length). However, in the context of the
        /// >           [`PlatformRef`] trait, we automatically consider as non-supported a
        /// >           multiaddress that contains a non-UTF-8 domain name, for the sake of
        /// >           simplicity.
        hostname: &'a str,
        /// TCP port to connect to.
        port: u16,
    },

    /// TCP/IP connection with an IP address.
    TcpIp {
        /// IP address to connect to.
        ip: IpAddr,
        /// TCP port to connect to.
        port: u16,
    },

    /// WebSocket connection with an IP address.
    WebSocketIp {
        /// IP address to connect to.
        ip: IpAddr,
        /// TCP port to connect to.
        port: u16,
    },

    /// WebSocket connection with a domain name.
    WebSocketDns {
        /// DNS hostname to connect to.
        ///
        /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
        /// >           string. Any binary data can be used as a domain name, provided it follows
        /// >           a few restrictions (notably its length). However, in the context of the
        /// >           [`PlatformRef`] trait, we automatically consider as non-supported a
        /// >           multiaddress that contains a non-UTF-8 domain name, for the sake of
        /// >           simplicity.
        hostname: &'a str,
        /// TCP port to connect to.
        port: u16,
        /// `true` for WebSocket secure connections.
        secure: bool,
    },
}

/// Address passed to [`PlatformRef::connect_multistream`].
// TODO: we don't differentiate between Dns4 and Dns6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiStreamAddress<'a> {
    /// Raw bidirectional WebTransport streams. No handshake or framing is added.
    WebTransport {
        /// IP address to connect to.
        ip: IpAddr,
        /// UDP port to connect to.
        port: u16,
        /// Non-empty list of SHA-256 hashes of acceptable DER server certificates.
        cert_hashes: Cow<'a, [[u8; 32]]>,
    },
    /// Libp2p-specific WebRTC flavour.
    ///
    /// The implementation the [`PlatformRef`] trait is responsible for opening the SCTP
    /// connection. The API user of the [`PlatformRef`] trait is responsible for opening the first
    /// data channel and performing the Noise handshake.
    // TODO: maybe explain more what the implementation is supposed to do?
    WebRtc {
        /// IP address to connect to.
        ip: IpAddr,
        /// UDP port to connect to.
        port: u16,
        /// SHA-256 hash of the target's WebRTC certificate.
        remote_certificate_sha256: &'a [u8; 32],
    },
}

// TODO: find a way to keep this private somehow?
#[macro_export]
macro_rules! log_inner {
    () => {
        core::iter::empty()
    };
    (,) => {
        core::iter::empty()
    };
    ($key:ident = $value:expr) => {
        $crate::log_inner!($key = $value,)
    };
    ($key:ident = ?$value:expr) => {
        $crate::log_inner!($key = ?$value,)
    };
    ($key:ident) => {
        $crate::log_inner!($key = $key,)
    };
    (?$key:ident) => {
        $crate::log_inner!($key = ?$key,)
    };
    ($key:ident = $value:expr, $($rest:tt)*) => {
        core::iter::once((stringify!($key), &$value as &dyn core::fmt::Display)).chain($crate::log_inner!($($rest)*))
    };
    ($key:ident = ?$value:expr, $($rest:tt)*) => {
        core::iter::once((stringify!($key), &format_args!("{:?}", $value) as &dyn core::fmt::Display)).chain($crate::log_inner!($($rest)*))
    };
    ($key:ident, $($rest:tt)*) => {
        $crate::log_inner!($key = $key, $($rest)*)
    };
    (?$key:ident, $($rest:tt)*) => {
        $crate::log_inner!($key = ?$key, $($rest)*)
    };
}

/// Helper macro for using the [`crate::platform::PlatformRef::log`] function.
///
/// This macro takes at least 4 parameters:
///
/// - A reference to an implementation of the [`crate::platform::PlatformRef`] trait.
/// - A log level: `Error`, `Warn`, `Info`, `Debug`, or `Trace`. See [`crate::platform::LogLevel`].
/// - A `&str` representing the target of the logging. This can be used in order to filter log
/// entries belonging to a specific target.
/// - An object that implements of `AsRef<str>` and that contains the log message itself.
///
/// In addition to these parameters, the macro accepts an unlimited number of extra
/// (comma-separated) parameters.
///
/// Each parameter has one of these four syntaxes:
///
/// - `key = value`, where `key` is an identifier and `value` an expression that implements the
/// `Display` trait.
/// - `key = ?value`, where `key` is an identifier and `value` an expression that implements
/// the `Debug` trait.
/// - `key`, which is syntax sugar for `key = key`.
/// - `?key`, which is syntax sugar for `key = ?key`.
///
#[macro_export]
macro_rules! log {
    ($plat:expr, $level:ident, $target:expr, $message:expr) => {
        log!($plat, $level, $target, $message,)
    };
    ($plat:expr, $level:ident, $target:expr, $message:expr, $($params:tt)*) => {
        $crate::platform::PlatformRef::log(
            $plat,
            $crate::platform::LogLevel::$level,
            $target,
            AsRef::<str>::as_ref(&$message),
            $crate::log_inner!($($params)*)
        )
    };
}
