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
//! # About wasi
//!
//! The Rust code is expected to be compiled for the `wasm32-wasi` target, and not just
//! `wasm32-unknown-unknown`. The `wasi` platform is used in order for example to obtain a source
//! of randomness.
//!
//! > **Note**: While wasi could theoretically also be used in order to obtain the current time,
//! >           the Wasi syscall cannot be implemented in pure JavaScript code at the moment, due
//! >           to `u64`s being unusable in JavaScript. As such, alternatives are present in the
//! >           `extern` block below.
//!
//! Consequently, the exports found in the `extern` block below are not the only functions that
//! must be implemented. Several functions required by the Wasi ABI are also used. The best place
//! to find documentation at the moment is <https://docs.rs/wasi>.
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
//! for example the return value of [`alloc`]. When using JavaScript as the host, you must do
//! `>>> 0` on all the `u32` values before interpreting them, in order to be certain than they
//! are treated as unsigned integers by the JavaScript.
//!

#[link(wasm_import_module = "smoldot")]
extern "C" {
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
    pub fn panic(message_ptr: u32, message_len: u32);

    /// Client is emitting a response to a previous JSON-RPC request sent using [`json_rpc_send`].
    /// Also used to send subscriptions notifications.
    ///
    /// The response or notification is a UTF-8 string found in the memory of the WebAssembly
    /// virtual machine at offset `ptr` and with length `len`. `chain_id` is the chain
    /// that the request was made to.
    pub fn json_rpc_respond(ptr: u32, len: u32, chain_id: u32);

    /// This function is called by the client is response to calling [`database_content`].
    ///
    /// The database content is a UTF-8 string found in the memory of the WebAssembly virtual
    /// machine at offset `ptr` and with length `len`.
    ///
    /// `chain_id` is the chain that the request was made to. It is guaranteed to always be valid.
    /// This function is not called if the chain is removed with [`remove_chain`] while the fetch
    /// is in progress.
    pub fn database_content_ready(ptr: u32, len: u32, chain_id: u32);

    /// Client is emitting a log entry.
    ///
    /// Each log entry is made of a log level (`1 = Error, 2 = Warn, 3 = Info, 4 = Debug,
    /// 5 = Trace`), a log target (e.g. "network"), and a log message.
    ///
    /// The log target and message is a UTF-8 string found in the memory of the WebAssembly
    /// virtual machine at offset `ptr` and with length `len`.
    pub fn log(level: u32, target_ptr: u32, target_len: u32, message_ptr: u32, message_len: u32);

    /// Must return the number of milliseconds that have passed since the UNIX epoch, ignoring
    /// leap seconds.
    ///
    /// This is typically implemented by calling `Date.now()`.
    ///
    /// See <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now>
    ///
    /// > **Note**: Ideally this function isn't needed. The wasi target supports clocks through
    /// >           the `clock_time_get` syscall. However, since `clock_time_get` uses `u64s`, and
    /// >           browsers don't support `u64s`, using it causes an unbypassable exception. See
    /// >           also <https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370>.
    pub fn unix_time_ms() -> f64;

    /// Must return the number of milliseconds that have passed since an arbitrary point in time.
    ///
    /// Contrary to [`unix_time_ms`], the returned value must never be inferior to a value
    /// previously returned. Consequently, this must not be implemented using `Date.now()`, whose
    /// value can decrease if the user adjusts their machine's clock, but rather with
    /// `Performance.now()` or similar.
    ///
    /// See <https://developer.mozilla.org/fr/docs/Web/API/Performance/now>
    ///
    /// > **Note**: Ideally this function isn't needed. The wasi target supports clocks through
    /// >           the `clock_time_get` syscall. However, since `clock_time_get` uses `u64s`, and
    /// >           browsers don't support `u64s`, using it causes an unbypassable exception. See
    /// >           also <https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370>.
    pub fn monotonic_clock_ms() -> f64;

    /// After at least `milliseconds` milliseconds have passed, must call [`timer_finished`] with
    /// the `id` passed as parameter.
    ///
    /// It is not a logic error to call [`timer_finished`] *before* `milliseconds` milliseconds
    /// have passed, and this will likely cause smoldot to restart a new timer for the remainder
    /// of the duration.
    ///
    /// When [`timer_finished`] is called, the value of [`monotonic_clock_ms`] must have increased
    /// by at least the given number of `milliseconds`.
    ///
    /// If `milliseconds` is 0, [`timer_finished`] should be called as soon as possible.
    pub fn start_timer(id: u32, milliseconds: f64);

    /// Must initialize a new connection that tries to connect to the given multiaddress.
    ///
    /// The multiaddress is a UTF-8 string found in the WebAssembly memory at offset `addr_ptr`
    /// and with `addr_len` bytes. The string is a multiaddress such as `/ip4/1.2.3.4/tcp/5/ws`.
    ///
    /// The `id` parameter is an identifier for this connection, as chosen by the Rust code. It
    /// must be passed on every interaction with this connection.
    ///
    /// Returns 0 to indicate success, or 1 to indicate that an error happened. If an error is
    /// returned, the `id` doesn't correspond to anything.
    ///
    /// > **Note**: If you implement this function using for example `new WebSocket()`, please
    /// >           keep in mind that exceptions should be caught and turned into an error code.
    ///
    /// The `error_ptr_ptr` parameter should be treated as a pointer to two consecutive
    /// little-endian 32-bits unsigned numbers and a 8-bits unsigned number. If an error happened,
    /// call [`alloc`] to allocate memory, write a UTF-8 error message in that given location,
    /// then write that location at the location indicated by `error_ptr_ptr` and the length of
    /// that string at the location `error_ptr_ptr + 4`. The buffer will be de-allocated by the
    /// client. Then, write at location `error_ptr_ptr + 8` a `1` if the error is caused by the
    /// address being forbidden or unsupported, and `0` otherwise. If no error happens, nothing
    /// should be written to `error_ptr_ptr`.
    ///
    /// At any time, a connection can be in one of the three following states:
    ///
    /// - `Opening` (initial state)
    /// - `Open`
    /// - `Closed`
    ///
    /// When in the `Opening` or `Open` state, the connection can transition to the `Closed` state
    /// if the remote closes the connection or refuses the connection altogether. When that
    /// happens, [`connection_closed`] must be called. Once in the `Closed` state, the connection
    /// cannot transition back to another state.
    ///
    /// Initially in the `Opening` state, the connection can transition to the `Open` state if the
    /// remote accepts the connection. When that happens, [`connection_open_single_stream`] or
    /// [`connection_open_multi_stream`] must be called.
    ///
    /// There exists two kind of connections: single-stream and multi-stream. Single-stream
    /// connections are assumed to have a single stream open at all time and the encryption and
    /// multiplexing are handled internally by smoldot. Multi-stream connections open and close
    /// streams over time using [`connection_stream_opened`] and [`stream_closed`], and the
    /// encryption and multiplexing are handled by the user of these bindings.
    pub fn connection_new(id: u32, addr_ptr: u32, addr_len: u32, error_ptr_ptr: u32) -> u32;

    /// Close a connection previously initialized with [`connection_new`].
    ///
    /// This destroys the identifier passed as parameter. This identifier must never be passed
    /// through the FFI boundary, unless the same identifier is later allocated again with
    /// [`connection_new`].
    ///
    /// The connection must be closed in the background. The Rust code isn't interested in incoming
    /// messages from this connection anymore.
    ///
    /// > **Note**: In JavaScript, remember to unregister event handlers before calling for
    /// >           example `WebSocket.close()`.
    pub fn connection_close(id: u32);

    /// Queues a new outbound substream opening. The [`connection_stream_opened`] function must
    /// later be called when the substream has been successfully opened.
    ///
    /// This function will only be called for multi-stream connections. The connection must
    /// currently be in the `Open` state. See the documentation of [`connection_new`] for details.
    pub fn connection_stream_open(connection_id: u32);

    /// Closes an existing substream of a multi-stream connection. The substream must currently
    /// be in the `Open` state.
    ///
    /// This function will only be called for multi-stream connections. The connection must
    /// currently be in the `Open` state. See the documentation of [`connection_new`] for details.
    pub fn connection_stream_close(connection_id: u32, stream_id: u32);

    /// Queues data on the given stream. The data is found in the memory of the WebAssembly
    /// virtual machine, at the given pointer. The data must be sent as a binary frame.
    ///
    /// If `connection_id` is a single-stream connection, then the value of `stream_id` should
    /// be ignored. If `connection_id` is a multi-stream connection, then the value of `stream_id`
    /// contains the identifier of the stream on which to send the data, as was provided to
    /// [`connection_stream_opened`].
    ///
    /// The connection associated with that stream (and, in the case of a multi-stream connection,
    /// the stream itself must currently be in the `Open` state. See the documentation of
    /// [`connection_new`] for details.
    pub fn stream_send(connection_id: u32, stream_id: u32, ptr: u32, len: u32);

    /// Called when the Wasm execution enters the context of a certain task. This is useful for
    /// debugging purposes.
    ///
    /// Only one task can be currently executing at any time.
    ///
    /// The name of the task is a UTF-8 string found in the memory of the WebAssembly virtual
    /// machine at offset `ptr` and with length `len`.
    ///
    /// This function is called only if `enable_current_task` was non-zero when calling [`init`].
    pub fn current_task_entered(ptr: u32, len: u32);

    /// Called when the Wasm execution leave the context of a certain task. This is useful for
    /// debugging purposes.
    ///
    /// Only one task can be currently executing at any time.
    ///
    /// This function is called only if `enable_current_task` was non-zero when calling [`init`].
    pub fn current_task_exit();
}

/// Initializes the client.
///
/// This is the first function that must be called. Failure to do so before calling another
/// method will lead to a Rust panic. Calling this function multiple times will also lead to a
/// panic.
///
/// The client will emit log messages by calling the [`log()`] function, provided the log level is
/// inferior or equal to the value of `max_log_level` passed here.
///
/// If `enbable_current_task` is non-zero, smoldot will call the [`current_task_entered`] and
/// [`current_task_exit`] functions to report when it enters and leaves tasks. This slightly
/// slows everything down, but is useful for debugging purposes.
///
/// `cpu_rate_limit` can be used to limit the amount of CPU that smoldot will use on average.
/// `u32::max_value()` represents "one CPU". For example passing `rate_limit / 2` represents
/// "`50%` of one CPU".
#[no_mangle]
pub extern "C" fn init(max_log_level: u32, enable_current_task: u32, cpu_rate_limit: u32) {
    crate::init(max_log_level, enable_current_task, cpu_rate_limit)
}

/// Instructs the client to start shutting down.
///
/// Later, the client will use `exit` to stop.
///
/// It is still legal to call all the other functions of these bindings. The client continues to
/// operate normally until the call to `exit`, which happens at some point in the future.
// TODO: can this be called multiple times?
#[no_mangle]
pub extern "C" fn start_shutdown() {
    crate::start_shutdown()
}

/// Allocates a buffer of the given length, with an alignment of 1.
///
/// This must be used in the context of [`add_chain`] and other functions that similarly require
/// passing data of variable length.
///
/// > **Note**: If using JavaScript as the host, you likely need to perform `>>> 0` on the return
/// >           value. See the module-level documentation.
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> u32 {
    let len = usize::try_from(len).unwrap();
    let mut vec = Vec::<u8>::with_capacity(len);
    unsafe {
        vec.set_len(len);
    }
    let ptr: *mut [u8] = Box::into_raw(vec.into_boxed_slice());
    u32::try_from(ptr as *mut u8 as usize).unwrap()
}

/// Adds a chain to the client. The client will try to stay connected and synchronize this chain.
///
/// Use [`alloc`] to allocate a buffer for the spec and the database of the chain that needs to
/// be started. Write the chain spec and database content in these buffers as UTF-8. Then, pass
/// the pointers and lengths (in bytes) as parameter to this function.
///
/// > **Note**: The database content is an opaque string that can be obtained by calling
/// >           [`database_content`].
///
/// Similarly, use [`alloc`] to allocate a buffer containing a list of 32-bits-little-endian chain
/// ids. Pass the pointer and number of chain ids (*not* length in bytes of the buffer) to this
/// function. If the chain specification refer to a parachain, these chain ids are the ones that
/// will be looked up to find the corresponding relay chain.
///
/// These three buffers **must** have been allocated with [`alloc`]. They are freed when this
/// function is called, even if an error code is returned.
///
/// If `json_rpc_running` is 0, then no JSON-RPC service will be started and it is forbidden to
/// send JSON-RPC requests targeting this chain. This can be used to save up resources.
///
/// If an error happens during the creation of the chain, a chain id will be allocated
/// nonetheless, and must later be de-allocated by calling [`remove_chain`]. This allocated chain,
/// however, will be in an erroneous state. Use [`chain_is_ok`] to determine whether this function
/// was successful. If not, use [`chain_error_len`] and [`chain_error_ptr`] to obtain the error
/// message.
#[no_mangle]
pub extern "C" fn add_chain(
    chain_spec_pointer: u32,
    chain_spec_len: u32,
    database_content_pointer: u32,
    database_content_len: u32,
    json_rpc_running: u32,
    potential_relay_chains_ptr: u32,
    potential_relay_chains_len: u32,
) -> u32 {
    super::add_chain(
        chain_spec_pointer,
        chain_spec_len,
        database_content_pointer,
        database_content_len,
        json_rpc_running,
        potential_relay_chains_ptr,
        potential_relay_chains_len,
    )
}

/// Removes a chain previously added using [`add_chain`]. Instantly unsubscribes all the JSON-RPC
/// subscriptions and cancels all in-progress requests corresponding to that chain.
///
/// If the removed chain was an erroneous chain, calling this function will invalidate the pointer
/// returned by [`chain_error_ptr`].
#[no_mangle]
pub extern "C" fn remove_chain(chain_id: u32) {
    super::remove_chain(chain_id)
}

/// Returns `1` if creating this chain was successful. Otherwise, returns `0`.
///
/// If `0` is returned, use [`chain_error_len`] and [`chain_error_ptr`] to obtain an error
/// message.
#[no_mangle]
pub extern "C" fn chain_is_ok(chain_id: u32) -> u32 {
    super::chain_is_ok(chain_id)
}

/// Returns the length of the error message stored for this chain.
///
/// Must only be called on an erroneous chain. Use [`chain_is_ok`] to determine whether a chain is
/// in an erroneous state. Returns `0` if the chain isn't erroneous.
#[no_mangle]
pub extern "C" fn chain_error_len(chain_id: u32) -> u32 {
    super::chain_error_len(chain_id)
}

/// Returns a pointer to the error message stored for this chain. The error message is a UTF-8
/// string starting at the memory offset returned by this function, and whose length can be
/// determined by calling [`chain_error_len`].
///
/// Must only be called on an erroneous chain. Use [`chain_is_ok`] to determine whether a chain is
/// in an erroneous state. Returns `0` if the chain isn't erroneous.
#[no_mangle]
pub extern "C" fn chain_error_ptr(chain_id: u32) -> u32 {
    super::chain_error_ptr(chain_id)
}

/// Emit a JSON-RPC request or notification towards the given chain previously added using
/// [`add_chain`].
///
/// A buffer containing a UTF-8 JSON-RPC request or notification must be passed as parameter. The
/// format of the JSON-RPC requests and notifications is described in
/// [the standard JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification).
/// Requests that are not valid JSON-RPC are silently ignored.
///
/// The buffer passed as parameter **must** have been allocated with [`alloc`]. It is freed when
/// this function is called.
///
/// Responses and notifications are sent back using [`json_rpc_respond`].
///
/// It is forbidden to call this function on an erroneous chain or a chain that was created with
/// `json_rpc_running` equal to 0.
#[no_mangle]
pub extern "C" fn json_rpc_send(text_ptr: u32, text_len: u32, chain_id: u32) {
    super::json_rpc_send(text_ptr, text_len, chain_id)
}

/// Starts generating the content of the database of the chain.
///
/// This function doesn't immediately return the content, but later calls
/// [`database_content_ready`] with the content of the database.
///
/// Calling this function multiple times will lead to multiple calls to [`database_content_ready`],
/// with potentially different values.
///
/// The `max_size` parameter contains the maximum length, in bytes, of the value that will be
/// provided back. Please be aware that passing a `u32` across the FFI boundary can be tricky.
/// From the Wasm perspective, the parameter of this function is actually a `i32` that is then
/// reinterpreted as a `u32`.
///
/// [`database_content_ready`] will not be called if you remove the chain with [`remove_chain`]
/// while the operation is in progress.
///
/// It is forbidden to call this function on an erroneous chain.
#[no_mangle]
pub extern "C" fn database_content(chain_id: u32, max_size: u32) {
    super::database_content(chain_id, max_size)
}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[no_mangle]
pub extern "C" fn timer_finished(timer_id: u32) {
    crate::timers::timer_finished(timer_id);
}

/// Called by the JavaScript code if the connection switches to the `Open` state. The connection
/// must be in the `Opening` state.
///
/// Must be called at most once per connection object.
///
/// See also [`connection_new`].
///
/// When in the `Open` state, the connection can receive messages. When a message is received,
/// [`alloc`] must be called in order to allocate memory for this message, then
/// [`stream_message`] must be called with the pointer returned by [`alloc`].
///
/// The `handshake_ty` parameter indicates the type of handshake. It must always be 0 at the
/// moment, indicating a multistream-select+Noise+Yamux handshake.
#[no_mangle]
pub extern "C" fn connection_open_single_stream(connection_id: u32, handshake_ty: u32) {
    crate::platform::connection_open_single_stream(connection_id, handshake_ty);
}

/// Called by the JavaScript code if the connection switches to the `Open` state. The connection
/// must be in the `Opening` state.
///
/// Must be called at most once per connection object.
///
/// See also [`connection_new`].
///
/// When in the `Open` state, the connection can receive messages. When a message is received,
/// [`alloc`] must be called in order to allocate memory for this message, then
/// [`stream_message`] must be called with the pointer returned by [`alloc`].
///
/// A "handshake type" must be provided. To do so, allocate a buffer with [`alloc`] and pass a
/// pointer to it. This buffer is freed when this function is called.
/// The buffer must contain a single 0 byte (indicating WebRTC), followed with the multihash
/// representation of the hash of the local node's TLS certificate, followed with the multihash
/// representation of the hash of the remote node's TLS certificate.
#[no_mangle]
pub extern "C" fn connection_open_multi_stream(
    connection_id: u32,
    handshake_ty_ptr: u32,
    handshake_ty_len: u32,
) {
    crate::platform::connection_open_multi_stream(connection_id, handshake_ty_ptr, handshake_ty_len)
}

/// Notify of a message being received on the stream. The connection associated with that stream
/// (and, in the case of a multi-stream connection, the stream itself) must be in the `Open` state.
///
/// If `connection_id` is a single-stream connection, then the value of `stream_id` is ignored.
/// If `connection_id` is a multi-stream connection, then `stream_id` corresponds to the stream
/// on which the data was received, as was provided to [`connection_stream_opened`].
///
/// See also [`connection_open_single_stream`] and [`connection_open_multi_stream`].
///
/// The buffer **must** have been allocated with [`alloc`]. It is freed when this function is
/// called.
#[no_mangle]
pub extern "C" fn stream_message(connection_id: u32, stream_id: u32, ptr: u32, len: u32) {
    crate::platform::stream_message(connection_id, stream_id, ptr, len)
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
pub extern "C" fn connection_stream_opened(connection_id: u32, stream_id: u32, outbound: u32) {
    crate::platform::connection_stream_opened(connection_id, stream_id, outbound)
}

/// Can be called at any point by the JavaScript code if the connection switches to the `Closed`
/// state.
///
/// Must only be called once per connection object.
///
/// Must be passed a UTF-8 string indicating the reason for closing. The buffer **must** have
/// been allocated with [`alloc`]. It is freed when this function is called.
///
/// See also [`connection_new`].
#[no_mangle]
pub extern "C" fn connection_closed(connection_id: u32, ptr: u32, len: u32) {
    crate::platform::connection_closed(connection_id, ptr, len)
}

/// Can be called at any point by the JavaScript code if the stream switches to the `Closed`
/// state.
///
/// Must only be called once per stream.
///
/// The `stream_id` becomes dead and can be re-used for another stream on the same connection.
///
/// It is illegal to call this function on a single-stream connections.
///
/// See also [`connection_open_multi_stream`].
#[no_mangle]
pub extern "C" fn stream_closed(connection_id: u32, stream_id: u32) {
    crate::platform::stream_closed(connection_id, stream_id)
}
