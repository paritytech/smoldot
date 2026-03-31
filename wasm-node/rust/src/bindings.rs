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

//! Imports and exports of the WebAssembly module.
//!
//! This module contains all the functions that tie together the Rust code and its host (i.e.
//! the JavaScript code, normally).
//!
//! The functions found in the `extern` block are the functions that the Rust code *imports*, and
//! need to be implemented on the host side and provided to the WebAssembly virtual machine. The
//! other functions are functions that the Rust code *exports*, and can be called by the host.
//!
//! # Re-entrency
//!
//! As a rule, none of the implementations of the functions that the host provides is allowed
//! to call a function exported by Rust.
//!
//! For example, the implementation of [`start_timer`] isn't allowed to call [`timer_finished`].
//! Instead, it must return, and later [`timer_finished`] be called independently.
//!
//! This avoids potential stack overflows and tricky borrowing-related situations.
//!
//! # About `u32`s and JavaScript
//!
//! Many functions below accept as parameter or return a `u32`. In reality, however, the
//! WebAssembly specification doesn't mention unsigned integers. Only signed integers (and
//! floating points) can be passed through the FFI layer.
//!
//! This isn't important when the Rust code provides a value that must later be provided back, as
//! the conversion from the guest to the host is symmetrical to the conversion from the host to
//! the guest.
//!
//! It is, however, important when the value needs to be interpreted from the host side, such as
//! for example the `message_ptr` parameter of [`panic()`]. When using JavaScript as the host, you
//! must do `>>> 0` on all the `u32` values before interpreting them, in order to be certain than
//! they are treated as unsigned integers by the JavaScript.
//!

use alloc::boxed::Box;

#[link(wasm_import_module = "smoldot")]
unsafe extern "C" {
    /// Must stop the execution immediately. The message is a UTF-8 string found in the memory of
    /// the WebAssembly at offset `message_ptr` and with length `message_len`.
    ///
    /// > **Note**: This function is typically implemented using `throw`.
    ///
    /// After this function has been called, no further Wasm functions must be called again on
    /// this Wasm virtual machine. Explanation below.
    ///
    /// # About throwing and safety
    ///
    /// Rust programs can be configured in two panicking modes: `abort`, or `unwind`. Safe or
    /// unsafe Rust code must be written by keeping in mind that the execution of a function can
    /// be suddenly interrupted by a panic, but can rely on the fact that this panic will either
    /// completely abort the program, or unwind the stack. In the latter case, they can rely on
    /// the fact that `std::panic::catch_unwind` will catch this unwinding and let them perform
    /// some additional clean-ups.
    ///
    /// This function is typically implemented using `throw`. However, "just" throwing a JavaScript
    /// exception from within the implementation of this function is neither `abort`, because the
    /// JavaScript could call into the Wasm again later, nor `unwind`, because it isn't caught by
    /// `std::panic::catch_unwind`. By being neither of the two, it breaks the assumptions that
    /// some Rust codes might rely on for either correctness or safety.
    /// In order to solve this problem, we enforce that `panic` must behave like `abort`, and
    /// forbid calling into the Wasm virtual machine again.
    ///
    /// Beyond the `panic` function itself, any other FFI function that throws must similarly
    /// behave like `abort` and prevent any further execution.
    pub unsafe fn panic(message_ptr: u32, message_len: u32);

    /// Called in response to [`add_chain`] once the initialization of the chain is complete.
    ///
    /// If `error_msg_ptr` is equal to 0, then the chain initialization is successful. Otherwise,
    /// `error_msg_ptr` and `error_msg_len` designate a buffer in the memory of the WebAssembly
    /// virtual machine where a UTF-8 diagnostic error message can be found.
    pub safe fn chain_initialized(chain_id: u32, error_msg_ptr: u32, error_msg_len: u32);

    /// Fills the buffer of the WebAssembly virtual machine with random data, starting at `ptr`
    /// and for `len` bytes.
    ///
    /// This data will be used in order to generate secrets. Do not use a dummy implementation!
    pub unsafe fn random_get(ptr: u32, len: u32);

    /// Returns the system clock in number of microseconds since the UNIX epoch, ignoring leap
    /// seconds.
    ///
    /// This clock is allowed to go backwards.
    ///
    /// Must never return a negative number. Implementers should be aware that the system clock
    /// can be negative, and abort execution if that is the case.
    pub safe fn unix_timestamp_us() -> u64;

    /// Returns the number of microseconds since an especified point in time. Must never decrease
    /// over time.
    pub safe fn monotonic_clock_us() -> u64;

    /// Copies the entire content of the buffer with the given index to the memory of the
    /// WebAssembly at offset `target_pointer`.
    ///
    /// In situations where a buffer must be provided from the JavaScript to the Rust code, the
    /// JavaScript must (prior to calling the Rust function that requires the buffer) assign a
    /// "buffer index" to the buffer it wants to provide. The Rust code then calls the
    /// [`buffer_size`] and [`buffer_copy`] functions in order to obtain the length and content
    /// of the buffer.
    pub unsafe fn buffer_copy(buffer_index: u32, target_pointer: u32);

    /// Returns the size (in bytes) of the buffer with the given index.
    ///
    /// See the documentation of [`buffer_copy`] for context.
    pub safe fn buffer_size(buffer_index: u32) -> u32;

    /// The queue of JSON-RPC responses of the given chain is no longer empty.
    ///
    /// This function is only ever called after [`json_rpc_responses_peek`] has returned a `len`
    /// of 0.
    ///
    /// This function might be called spuriously, however this behavior must not be relied upon.
    pub safe fn json_rpc_responses_non_empty(chain_id: u32);

    /// Client is emitting a log entry.
    ///
    /// Each log entry is made of a log level (`1 = Error, 2 = Warn, 3 = Info, 4 = Debug,
    /// 5 = Trace`), a log target (e.g. "network"), and a log message.
    ///
    /// The log target and message is a UTF-8 string found in the memory of the WebAssembly
    /// virtual machine at offset `ptr` and with length `len`.
    pub safe fn log(
        level: u32,
        target_ptr: u32,
        target_len: u32,
        message_ptr: u32,
        message_len: u32,
    );

    /// Called when [`advance_execution`] should be executed again.
    ///
    /// This function might be called from within [`advance_execution`], in which case
    /// [`advance_execution`] should be called again immediately after it returns.
    pub safe fn advance_execution_ready();

    /// After at least `milliseconds` milliseconds have passed, [`timer_finished`] must be called.
    ///
    /// It is not a logic error to call [`timer_finished`] *before* `milliseconds` milliseconds
    /// have passed, and this will likely cause smoldot to restart a new timer for the remainder
    /// of the duration.
    ///
    /// When [`timer_finished`] is called, the value of the monotonic clock (in the bindings)
    /// must have increased by at least the given number of `milliseconds`.
    ///
    /// If `milliseconds` is 0, [`timer_finished`] should be called as soon as possible.
    ///
    /// `milliseconds` never contains a negative number, `NaN` or infinite.
    pub safe fn start_timer(milliseconds: f64);

    /// Must return the host supports connecting to a certain type of address.
    ///
    /// The `ty` parameter is equal to the first byte of the encoded address that would be passed
    /// to [`connection_new`]. See [`connection_new`] for more information.
    ///
    /// An additional `ty` value of `7` is supported, and means "non-secure WebSocket connection
    /// to localhost".
    ///
    /// Returns a non-zero value if the address is supported. Returns `0` if the address isn't
    /// supported.
    pub safe fn connection_type_supported(ty: u8) -> u32;

    /// Must initialize a new connection that tries to connect to the given address.
    ///
    /// The address to connect to is in the WebAssembly memory at offset `addr_ptr` and with
    /// `addr_len` bytes. The format is as follows:
    ///
    /// - One `type` byte (see below).
    /// - Two big-endian bytes representing the port (either TCP or UDP depending on the `type`)
    ///   to connect to.
    /// - (optional) The 32 bytes SHA-256 hash of the certificate of the remote.
    /// - An UTF-8-encoded IP address or domain name. Use the `addr_len` parameter to determine
    ///   its length. When using an IPv4, it is encoded as `a.b.c.d`. When using an IPv6, it is
    ///   encoded according to RFC5952.
    ///
    /// The `type` byte defines the type of connection and whether the optional field is present:
    ///
    /// - `0`: TCP/IPv4 connection, with a port and an IPv4 address.
    /// - `1`: TCP/IPv6 connection, with a port and an IPv6 address.
    /// - `2`: TCP/IP connection, with a port and a domain name.
    /// - `4`: WebSocket connection, with a port and an IPv4 address.
    /// - `5`: WebSocket connection, with a port and an IPv6 address.
    /// - `6`: WebSocket connection, with a port and a domain name.
    /// - `14`: WebSocket secure connection, with a port and a domaine name.
    /// - `16`: WebRTC connection, with a port, an IPv4 address, and a remote certificate hash.
    /// - `17`: WebRTC connection, with a port, an IPv6 address, and a remote certificate hash.
    ///
    /// > **Note**: While these numbers seem arbitrary, they actually loosely follow a certain
    /// >           scheme. The lowest 2 bits indicate the type of IP address, while the highest
    /// >           bits indicate the type of connection.
    ///
    /// The `id` parameter is an identifier for this connection, as chosen by the Rust code. It
    /// must be passed on every interaction with this connection.
    ///
    /// At any time, a connection can be in either the `Open` (the initial state) or the `Reset`
    /// state.
    /// When in the `Open` state, the connection can transition to the `Reset` state if the remote
    /// closes the connection or refuses the connection altogether. When that happens,
    /// [`connection_reset`] must be called. Once in the `Reset` state, the connection cannot
    /// transition back to the `Open` state.
    ///
    /// If the connection is a multistream connection, then
    /// [`connection_multi_stream_set_handshake_info`] must later be called as soon as possible.
    ///
    /// There exists two kind of connections: single-stream and multi-stream. Single-stream
    /// connections are assumed to have a single stream open at all time and the encryption and
    /// multiplexing are handled internally by smoldot. Multi-stream connections open and close
    /// streams over time using [`connection_stream_opened`] and [`stream_reset`], and the
    /// encryption and multiplexing are handled by the user of these bindings.
    pub safe fn connection_new(id: u32, addr_ptr: u32, addr_len: u32);

    /// Abruptly close a connection previously initialized with [`connection_new`].
    ///
    /// This destroys the identifier passed as parameter. This identifier must never be passed
    /// through the FFI boundary, unless the same identifier is later allocated again with
    /// [`connection_new`].
    ///
    /// Must never be called if [`connection_reset`] has been called on that object in the past.
    ///
    /// The connection must be closed in the background. The Rust code isn't interested in incoming
    /// messages from this connection anymore.
    ///
    /// > **Note**: In JavaScript, remember to unregister event handlers before calling for
    /// >           example `WebSocket.close()`.
    pub safe fn reset_connection(id: u32);

    /// Queues a new outbound substream opening. The [`connection_stream_opened`] function must
    /// later be called when the substream has been successfully opened.
    ///
    /// This function will only be called for multi-stream connections. The connection must
    /// currently be in the `Open` state. See the documentation of [`connection_new`] for details.
    ///
    /// > **Note**: No mechanism exists in this API to handle the situation where a substream fails
    /// >           to open, as this is not supposed to happen. If you need to handle such a
    /// >           situation, either try again opening a substream again or reset the entire
    /// >           connection.
    pub safe fn connection_stream_open(connection_id: u32);

    /// Abruptly closes an existing substream of a multi-stream connection. The substream must
    /// currently be in the `Open` state.
    ///
    /// Must never be called if [`stream_reset`] has been called on that object in the past.
    ///
    /// This function will only be called for multi-stream connections. The connection must
    /// currently be in the `Open` state. See the documentation of [`connection_new`] for details.
    pub safe fn connection_stream_reset(connection_id: u32, stream_id: u32);

    /// Queues data on the given stream.
    ///
    /// `ptr` is a memory address where `len` consecutive elements of type [`StreamSendIoVector`]
    /// are found. Each element consists in two little-endian 32 bits unsigned integers: the first
    /// one is a pointer, and the second one is a length in bytes. The data to write on the stream
    /// consists in the concatenation of all these buffers.
    ///
    /// > **Note**: This interface is similar the famous UNIX function `writev`. `ptr` is the same
    /// >           as `iov`, and `len` the same as `iovcnt`.
    /// >           See <https://linux.die.net/man/2/writev>.
    ///
    /// If `connection_id` is a single-stream connection, then the value of `stream_id` should
    /// be ignored. If `connection_id` is a multi-stream connection, then the value of `stream_id`
    /// contains the identifier of the stream on which to send the data, as was provided to
    /// [`connection_stream_opened`].
    ///
    /// The connection associated with that stream (and, in the case of a multi-stream connection,
    /// the stream itself must currently be in the `Open` state. See the documentation of
    /// [`connection_new`] for details.
    ///
    /// The size of the buffer must not exceed the number of writable bytes of the given stream.
    /// Use [`stream_writable_bytes`] to notify that more data can be sent on the stream.
    pub safe fn stream_send(connection_id: u32, stream_id: u32, ptr: u32, len: u32);

    /// Close the sending side of the given stream of the given connection.
    ///
    /// Never called for connection types where this isn't possible to implement (i.e. WebSocket
    /// and WebRTC at the moment).
    ///
    /// If `connection_id` is a single-stream connection, then the value of `stream_id` should
    /// be ignored. If `connection_id` is a multi-stream connection, then the value of `stream_id`
    /// contains the identifier of the stream whose sending side should be closed, as was provided
    /// to [`connection_stream_opened`].
    ///
    /// The connection associated with that stream (and, in the case of a multi-stream connection,
    /// the stream itself must currently be in the `Open` state. See the documentation of
    /// [`connection_new`] for details.
    pub safe fn stream_send_close(connection_id: u32, stream_id: u32);

    /// Called when the Wasm execution enters the context of a certain task. This is useful for
    /// debugging purposes.
    ///
    /// Only one task can be currently executing at any time.
    ///
    /// The name of the task is a UTF-8 string found in the memory of the WebAssembly virtual
    /// machine at offset `ptr` and with length `len`.
    pub safe fn current_task_entered(ptr: u32, len: u32);

    /// Called when the Wasm execution leave the context of a certain task. This is useful for
    /// debugging purposes.
    ///
    /// Only one task can be currently executing at any time.
    pub safe fn current_task_exit();
}

/// See [`stream_send`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StreamSendIoVector {
    /// Pointer to a buffer of data to write.
    pub ptr: u32,
    /// Length of the buffer of data.
    pub len: u32,
}

/// Initializes the client.
///
/// This is the first function that must be called. Failure to do so before calling another
/// method will lead to a Rust panic. Calling this function multiple times will also lead to a
/// panic.
///
/// The client will emit log messages by calling the [`log()`] function, provided the log level is
/// inferior or equal to the value of `max_log_level` passed here.
#[unsafe(no_mangle)]
pub extern "C" fn init(max_log_level: u32) {
    crate::init(max_log_level);
}

/// Advances the execution of the client, performing CPU-heavy tasks.
///
/// This function **must** be called regularly, otherwise nothing will happen.
///
/// After this function is called or during a call to this function, [`advance_execution_ready`]
/// might be called, indicating that [`advance_execution`] should be called again.
#[unsafe(no_mangle)]
pub extern "C" fn advance_execution() {
    super::advance_execution()
}

/// Adds a chain to the client. The client will try to stay connected and synchronize this chain.
///
/// Assign a so-called "buffer index" (a `u32`) representing the chain specification, database
/// content, and list of potential relay chains, then provide these buffer indices to the function.
/// The Rust code will call [`buffer_size`] and [`buffer_copy`] in order to obtain the content of
/// these buffers. The buffer indices can be de-assigned and buffers destroyed once this function
/// returns.
///
/// The content of the chain specification and database content must be in UTF-8.
///
/// > **Note**: The database content is an opaque string that can be obtained by calling
/// >           the `chainHead_unstable_finalizedDatabase` JSON-RPC function.
///
/// The list of potential relay chains is a buffer containing a list of 32-bits-little-endian chain
/// ids. If the chain specification refer to a parachain, these chain ids are the ones that will be
/// looked up to find the corresponding relay chain.
///
/// `json_rpc_max_pending_requests` indicates the size of the queue of JSON-RPC requests that
/// haven't been answered yet.
/// If `json_rpc_max_pending_requests` is 0, then no JSON-RPC service will be started and it is
/// forbidden to send JSON-RPC requests targeting this chain. This can be used to save up
/// resources.
/// If `json_rpc_max_pending_requests` is 0, then the value of `json_rpc_max_subscriptions` is
/// ignored.
///
/// Calling this function allocates a chain id and starts the chain initialization in the
/// background. Once the initialization is complete, the [`chain_initialized`] function will be
/// called by smoldot.
/// It is possible to call [`remove_chain`] while the initialization is still in progress in
/// order to cancel it.
#[unsafe(no_mangle)]
pub extern "C" fn add_chain(
    chain_spec_buffer_index: u32,
    database_content_buffer_index: u32,
    json_rpc_max_pending_requests: u32,
    json_rpc_max_subscriptions: u32,
    potential_relay_chains_buffer_index: u32,
    statement_store_max_seen_statements: u32,
) -> u32 {
    super::add_chain(
        get_buffer(chain_spec_buffer_index),
        get_buffer(database_content_buffer_index),
        json_rpc_max_pending_requests,
        json_rpc_max_subscriptions,
        get_buffer(potential_relay_chains_buffer_index),
        statement_store_max_seen_statements,
    )
}

/// Removes a chain previously added using [`add_chain`]. Instantly unsubscribes all the JSON-RPC
/// subscriptions and cancels all in-progress requests corresponding to that chain.
///
/// Can be called on a chain which hasn't finished initializing yet.
#[unsafe(no_mangle)]
pub extern "C" fn remove_chain(chain_id: u32) {
    super::remove_chain(chain_id);
}

/// Emit a JSON-RPC request or notification towards the given chain previously added using
/// [`add_chain`].
///
/// A buffer containing a UTF-8 JSON-RPC request or notification must be passed as parameter. The
/// format of the JSON-RPC requests and notifications is described in
/// [the standard JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification).
///
/// If the buffer isn't a valid JSON-RPC request, then an error JSON-RPC response with an `id`
/// equal to `null` is generated, in accordance with the JSON-RPC 2.0 specification.
///
/// Assign a so-called "buffer index" (a `u32`) representing the buffer containing the UTF-8
/// request, then provide this buffer index to the function. The Rust code will call
/// [`buffer_size`] and [`buffer_copy`] in order to obtain the content of this buffer. The buffer
/// index can be de-assigned and buffer destroyed once this function returns.
///
/// Responses and notifications are notified using [`json_rpc_responses_non_empty`], and can
/// be read with [`json_rpc_responses_peek`].
///
/// It is forbidden to call this function on a chain which hasn't finished initializing yet or a
/// chain that was created with `json_rpc_running` equal to 0.
///
/// This function returns:
/// - 0 on success.
/// - 1 if the chain has too many pending JSON-RPC requests and refuses to queue another one.
///
#[unsafe(no_mangle)]
pub extern "C" fn json_rpc_send(text_buffer_index: u32, chain_id: u32) -> u32 {
    super::json_rpc_send(get_buffer(text_buffer_index), chain_id)
}

/// Obtains information about the first response in the queue of JSON-RPC responses.
///
/// This function returns a pointer within the memory of the WebAssembly virtual machine where is
/// stored a struct of type [`JsonRpcResponseInfo`]. This pointer remains valid until
/// [`json_rpc_responses_pop`] or [`remove_chain`] is called with the same `chain_id`.
///
/// The response or notification is a UTF-8 string found in the memory of the WebAssembly
/// virtual machine at offset `ptr` and with length `len`, where `ptr` and `len` are found in the
/// [`JsonRpcResponseInfo`].
///
/// If `len` is equal to 0, this indicates that the queue of JSON-RPC responses is empty.
/// When a `len` of 0 is returned, [`json_rpc_responses_non_empty`] will later be called to
/// indicate that it is no longer empty.
///
/// After having read the response or notification, use [`json_rpc_responses_pop`] to remove it
/// from the queue. You can then call [`json_rpc_responses_peek`] again to read the next response.
#[unsafe(no_mangle)]
pub extern "C" fn json_rpc_responses_peek(chain_id: u32) -> u32 {
    super::json_rpc_responses_peek(chain_id)
}

/// See [`json_rpc_responses_peek`].
#[repr(C)]
pub struct JsonRpcResponseInfo {
    /// Pointer in memory where the JSON-RPC response can be found.
    pub ptr: u32,
    /// Length of the JSON-RPC response in bytes. If 0, indicates that the queue is empty.
    pub len: u32,
}

/// Removes the first response from the queue of JSON-RPC responses. This is the response whose
/// information can be retrieved using [`json_rpc_responses_peek`].
///
/// Calling this function invalidates the pointer previously returned by a call to
/// [`json_rpc_responses_peek`] with the same `chain_id`.
///
/// It is forbidden to call this function on a chain that hasn't finished initializing yet, or a
/// chain that was created with `json_rpc_running` equal to 0.
#[unsafe(no_mangle)]
pub extern "C" fn json_rpc_responses_pop(chain_id: u32) {
    super::json_rpc_responses_pop(chain_id);
}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[unsafe(no_mangle)]
pub extern "C" fn timer_finished() {
    crate::timers::timer_finished();
}

/// Called by the JavaScript code in order to provide information about a multistream connection.
///
/// Must be called at most once per connection object.
///
/// See also [`connection_new`].
///
/// Assign a so-called "buffer index" (a `u32`) representing the buffer containing the handshake
/// type, then provide this buffer index to the function. The Rust code will call [`buffer_size`]
/// and [`buffer_copy`] in order to obtain the content of this buffer. The buffer index can be
/// de-assigned and buffer destroyed once this function returns.
///
/// The buffer must contain a single 0 byte (indicating WebRTC), followed with the SHA-256 hash of
/// the local node's TLS certificate.
#[unsafe(no_mangle)]
pub extern "C" fn connection_multi_stream_set_handshake_info(
    connection_id: u32,
    handshake_ty_buffer_index: u32,
) {
    crate::platform::connection_multi_stream_set_handshake_info(
        connection_id,
        get_buffer(handshake_ty_buffer_index),
    );
}

/// Notify of a message being received on the stream. The connection associated with that stream
/// (and, in the case of a multi-stream connection, the stream itself) must be in the `Open` state.
///
/// Assign a so-called "buffer index" (a `u32`) representing the buffer containing the message,
/// then provide this buffer index to the function. The Rust code will call [`buffer_size`] and
/// [`buffer_copy`] in order to obtain the content of this buffer. The buffer index can be
/// de-assigned and buffer destroyed once this function returns.
///
/// If `connection_id` is a single-stream connection, then the value of `stream_id` is ignored.
/// If `connection_id` is a multi-stream connection, then `stream_id` corresponds to the stream
/// on which the data was received, as was provided to [`connection_stream_opened`].
///
/// See also [`connection_new`].
#[unsafe(no_mangle)]
pub extern "C" fn stream_message(connection_id: u32, stream_id: u32, buffer_index: u32) {
    crate::platform::stream_message(connection_id, stream_id, get_buffer(buffer_index));
}

/// Notify that extra bytes can be written onto the stream. The connection associated with that
/// stream (and, in the case of a multi-stream connection, the stream itself) must be in the
/// `Open` state.
///
/// The total of writable bytes must not go beyond reasonable values (e.g. a few megabytes). It
/// is not legal to provide a dummy implementation that simply passes an exceedingly large value.
///
/// If `connection_id` is a single-stream connection, then the value of `stream_id` is ignored.
/// If `connection_id` is a multi-stream connection, then `stream_id` corresponds to the stream
/// on which the data was received, as was provided to [`connection_stream_opened`].
#[unsafe(no_mangle)]
pub extern "C" fn stream_writable_bytes(connection_id: u32, stream_id: u32, num_bytes: u32) {
    crate::platform::stream_writable_bytes(connection_id, stream_id, num_bytes);
}

/// Called by the JavaScript code when the given multi-stream connection has a new substream.
///
/// `connection_id` *must* be a multi-stream connection.
///
/// The value of `stream_id` is chosen at the discretion of the caller. It is illegal to use the
/// same `stream_id` as an existing stream on that same connection that is still open.
///
/// For the `outbound` parameter, pass `0` if the substream has been opened by the remote, and any
/// value other than `0` if the substream has been opened in response to a call to
/// [`connection_stream_open`].
#[unsafe(no_mangle)]
pub extern "C" fn connection_stream_opened(connection_id: u32, stream_id: u32, outbound: u32) {
    crate::platform::connection_stream_opened(connection_id, stream_id, outbound);
}

/// Can be called at any point by the JavaScript code if the connection switches to the `Reset`
/// state.
///
/// Must only be called once per connection object.
/// Must never be called if [`reset_connection`] has been called on that object in the past.
///
/// Assign a so-called "buffer index" (a `u32`) representing the buffer containing the UTF-8
/// reason for closing, then provide this buffer index to the function. The Rust code will call
/// [`buffer_size`] and [`buffer_copy`] in order to obtain the content of this buffer. The buffer
/// index can be de-assigned and buffer destroyed once this function returns.
///
/// See also [`connection_new`].
#[unsafe(no_mangle)]
pub extern "C" fn connection_reset(connection_id: u32, buffer_index: u32) {
    crate::platform::connection_reset(connection_id, get_buffer(buffer_index));
}

/// Can be called at any point by the JavaScript code if the stream switches to the `Reset`
/// state.
///
/// Must only be called once per stream.
/// Must never be called if [`connection_stream_reset`] has been called on that object in the past.
///
/// The `stream_id` becomes dead and can be re-used for another stream on the same connection.
///
/// It is illegal to call this function on a single-stream connections.
///
/// Assign a so-called "buffer index" (a `u32`) representing the buffer containing the UTF-8
/// reason for closing, then provide this buffer index to the function. The Rust code will call
/// [`buffer_size`] and [`buffer_copy`] in order to obtain the content of this buffer. The buffer
/// index can be de-assigned and buffer destroyed once this function returns.
///
/// See also [`connection_new`].
#[unsafe(no_mangle)]
pub extern "C" fn stream_reset(connection_id: u32, stream_id: u32, buffer_index: u32) {
    crate::platform::stream_reset(connection_id, stream_id, get_buffer(buffer_index));
}

pub(crate) fn get_buffer(buffer_index: u32) -> Box<[u8]> {
    unsafe {
        let len = usize::try_from(buffer_size(buffer_index)).unwrap();

        let mut buffer = Box::<[u8]>::new_uninit_slice(len);
        buffer_copy(buffer_index, buffer.as_mut_ptr().addr() as u32);
        buffer.assume_init()
    }
}
