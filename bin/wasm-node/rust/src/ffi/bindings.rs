// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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
//! >           to `u64`s being unusable in Javascript. As such, alternatives are present in the
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
    /// Must throw an exception. The message is a UTF-8 string found in the memory of the
    /// WebAssembly at offset `message_ptr` and with length `message_len`.
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
    /// Calling `throw` is neither `abort`, because the JavaScript could call into the Wasm again
    /// later, nor `unwind`, because it isn't caught by `std::panic::catch_unwind`. By being
    /// neither of the two, it breaks the assumptions that some Rust codes might rely on for
    /// either correctness or safety.
    /// In order to solve this problem, we enforce that `throw` must behave like `abort`, and
    /// forbid calling into the Wasm virtual machine again.
    ///
    /// Beyond the `throw` function itself, any other FFI function that throws must similarly
    /// behave like `abort` and prevent any further execution.
    pub fn throw(message_ptr: u32, message_len: u32);

    /// Client is emitting a response to a previous JSON-RPC request sent using [`json_rpc_send`].
    /// Also used to send subscriptions notifications.
    ///
    /// The response or notification is a UTF-8 string found in the memory of the WebAssembly
    /// virtual machine at offset `ptr` and with length `len`. `chain_id` is the chain
    /// that the request was made to.
    pub fn json_rpc_respond(ptr: u32, len: u32, chain_id: u32);

    /// Client is emitting a log entry.
    ///
    /// Each log entry is made of a log level (1 = Error, 2 = Warn, 3 = Info, 4 = Debug,
    /// 5 = Trace), a log target (e.g. "network"), and a log message.
    ///
    /// The log target and message is a UTF-8 string found in the memory of the WebAssembly
    /// virtual machine at offset `ptr` and with length `len`.
    pub fn log(level: u32, target_ptr: u32, target_len: u32, message_ptr: u32, message_len: u32);

    /// Must return the number of milliseconds that have passed since the UNIX epoch, ignoring
    /// leap seconds.
    ///
    /// This is typically implemented by calling `Date.now()`.
    ///
    /// See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now
    ///
    /// > **Note**: Ideally this function isn't needed. The wasi target supports clocks through
    /// >           the `clock_time_get` syscall. However, since `clock_time_get` uses u64s, and
    /// >           browsers don't support u64s, using it causes an unbypassable exception. See
    /// >           also <https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370>.
    pub fn unix_time_ms() -> f64;

    /// Must return the number of milliseconds that have passed since an arbitrary point in time.
    ///
    /// Contrary to [`unix_time_ms`], the returned value must never be inferior to a value
    /// previously returned. Consequently, this must not be implemented using `Date.now()`, whose
    /// value can decrease if the user adjusts their machine's clock, but rather with
    /// `Performance.now()` or similar.
    ///
    /// See https://developer.mozilla.org/fr/docs/Web/API/Performance/now
    ///
    /// > **Note**: Ideally this function isn't needed. The wasi target supports clocks through
    /// >           the `clock_time_get` syscall. However, since `clock_time_get` uses u64s, and
    /// >           browsers don't support u64s, using it causes an unbypassable exception. See
    /// >           also <https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370>.
    pub fn monotonic_clock_ms() -> f64;

    /// After at least `milliseconds` milliseconds have passed, must call [`timer_finished`] with
    /// the `id` passed as parameter.
    ///
    /// When [`timer_finished`] is called, the value of [`monotonic_clock_ms`] must have increased
    /// by at least the given number of `milliseconds`.
    ///
    /// If `milliseconds` is 0, [`timer_finished`] should be called as soon as possible.
    pub fn start_timer(id: u32, milliseconds: f64);

    /// Must initialize a new connection that tries to connect to the given multiaddress.
    ///
    /// The multiaddress is a UTF-8 string found in the WebAssembly memory at offset `addr_ptr`
    /// and with `addr_len` bytes. The string is a multiaddres such as `/ip4/1.2.3.4/tcp/5/ws`.
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
    /// little-endian 32-bits unsigned numbers. If an error happened, call [`alloc`] to allocate
    /// memory, write a UTF-8 error message in that given location, then write that location at
    /// the location indicated by `error_ptr_ptr` and the length of that string at the location
    /// `error_ptr_ptr + 4`. The buffer is then de-allocated by the client. If no error happens,
    /// nothing should be written to `error_ptr_ptr`.
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
    /// remote accepts the connection. When that happens, [`connection_open`] must be called.
    ///
    /// When in the `Open` state, the connection can receive messages. When a message is received,
    /// [`alloc`] must be called in order to allocate memory for this message, then
    /// [`connection_message`] must be called with the pointer returned by [`alloc`].
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

    /// Queues data on the given connection. The data is found in the memory of the WebAssembly
    /// virtual machine, at the given pointer. The data must be sent as a binary frame.
    ///
    /// The connection must currently be in the `Open` state. See the documentation of
    /// [`connection_new`] for details.
    pub fn connection_send(id: u32, ptr: u32, len: u32);
}

/// Initializes the client.
///
/// This is the first function that must be called. Failure to do so before calling another
/// method will lead to a Rust panic. Calling this function multiple times will also lead to a
/// panic.
///
/// The client will emit log messages by calling the [`log()`] function, provided the log level is
/// inferior or equal to the value of `max_log_level` passed here.
#[no_mangle]
pub extern "C" fn init(max_log_level: u32) {
    super::init(max_log_level)
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
    super::alloc(len)
}

/// Adds a chain to the client. The client will try to stay connected and synchronize this chain.
///
/// Use [`alloc`] to allocate a buffer for the spec of the chain that needs to be started.
/// Write the chain spec in this buffer as UTF-8. Then, pass the pointer and length (in bytes)
/// as parameter to this function.
///
/// Similarly, use [`alloc`] to allocate a buffer containing a list of 32-bits-little-endian chain
/// ids. Pass the pointer and number of chain ids (*not* length in bytes of the buffer) to this
/// function. If the chain specification refer to a parachain, these chain ids are the ones that
/// will be looked up to find the corresponding relay chain.
///
/// These two buffers **must** have been allocated with [`alloc`]. They are freed when this
/// function is called, even if an error code is returned.
///
/// If `json_rpc_running` is 0, then no JSON-RPC service will be started and all JSON-RPC requests
/// targeting this chain will return an error. This can be used to save up resources.
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
    json_rpc_running: u32,
    potential_relay_chains_ptr: u32,
    potential_relay_chains_len: u32,
) -> u32 {
    super::add_chain(
        chain_spec_pointer,
        chain_spec_len,
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

/// Emit a JSON-RPC request towards the given chain previously added using [`add_chain`].
///
/// A buffer containing a UTF-8 JSON-RPC request must be passed as parameter. The format of the
/// JSON-RPC requests is described in
/// [the standard JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification). A pub-sub
/// extension is supported.
///
/// The buffer passed as parameter **must** have been allocated with [`alloc`]. It is freed when
/// this function is called.
///
/// Responses and subscriptions notifications are sent back using [`json_rpc_respond`].
#[no_mangle]
pub extern "C" fn json_rpc_send(text_ptr: u32, text_len: u32, chain_id: u32) {
    super::json_rpc_send(text_ptr, text_len, chain_id)
}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[no_mangle]
pub extern "C" fn timer_finished(timer_id: u32) {
    super::timer_finished(timer_id);
}

/// Called by the JavaScript code if the connection switches to the `Open` state. The connection
/// must be in the `Opening` state.
///
/// Must only be called once per connection object.
///
/// See also [`connection_open`].
#[no_mangle]
pub extern "C" fn connection_open(id: u32) {
    super::connection_open(id);
}

/// Notify of a message being received on the connection. The connection must be in the `Open`
/// state.
///
/// See also [`connection_open`].
///
/// The buffer **must** have been allocated with [`alloc`]. It is freed when this function is
/// called.
#[no_mangle]
pub extern "C" fn connection_message(id: u32, ptr: u32, len: u32) {
    super::connection_message(id, ptr, len)
}

/// Can be called at any point by the JavaScript code if the connection switches to the `Closed`
/// state.
///
/// Must only be called once per connection object.
///
/// Must be passed a UTF-8 string indicating the reason for closing. The buffer **must** have
/// been allocated with [`alloc`]. It is freed when this function is called.
///
/// See also [`connection_open`].
#[no_mangle]
pub extern "C" fn connection_closed(id: u32, ptr: u32, len: u32) {
    super::connection_closed(id, ptr, len)
}
