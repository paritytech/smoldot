// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

// TODO: explain reasons ^

use core::{convert::TryFrom as _, future::Future, slice, time::Duration};

#[link(wasm_import_module = "substrate-lite")]
extern "C" {
    /// Must throw an exception. The message is a UTF-8 string found in the memory of the
    /// WebAssembly at offset `message_ptr` and with length `message_len`.
    pub(crate) fn throw(message_ptr: u32, message_len: u32);

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
    /// >           also https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370.
    pub(crate) fn unix_time_ms() -> f64;

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
    /// >           also https://github.com/dcodeIO/webassembly/issues/26#issuecomment-410157370.
    pub(crate) fn monotonic_clock_ms() -> f64;

    /// After `milliseconds` milliseconds have passed, must call [`timer_finished`] with the `id`
    /// passed as parameter.
    ///
    /// When [`timer_finished`] is called, the value of [`monotonic_clock_ms`] must have increased
    /// by the given number of `milliseconds`.
    pub(crate) fn start_timer(id: u32, milliseconds: f64);

    /// Must initialize a new WebSocket connection that tries to connect to the given URL.
    ///
    /// The URL is a UTF-8 string found in the WebAssembly memory at offset `url_ptr` and with
    /// `url_len` bytes. The string is in a format suitable for
    /// [`new WebSocket()`](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket).
    ///
    /// The `id` parameter is an identifier for this WebSocket, as chosen by the Rust code. It
    /// must be passed on every interaction with this WebSocket.
    ///
    /// Returns 0 to indicate success, or 1 to indicate that an error happened. If an error is
    /// returned, the `id` doesn't correspond to anything.
    ///
    /// > **Note**: If you implement this function using `new WebSocket()`, please keep in mind
    /// >           that exceptions should be caught and turned into an error code.
    ///
    /// At any time, a WebSocket can be in one of the three following states:
    ///
    /// - `Opening` (initial state)
    /// - `Open`
    /// - `Closed`
    ///
    /// When in the `Opening` or `Open` state, the WebSocket can transition to the `Closed` state
    /// if the remote closes the connection or refuses the connection altogether. When that
    /// happens, [`websocket_closed`] must be called. Once in the `Closed` state, the WebSocket
    /// cannot transition back to another state.
    ///
    /// Initially in the `Opening` state, the WebSocket can transition to the `Open` state if the
    /// remote accepts the connection. When that happens, [`websocket_open`] must be called.
    ///
    /// When in the `Open` state, the WebSocket can receive messages. When a message is received,
    /// [`alloc`] must be called in order to allocate memory for this message, then
    /// [`websocket_message`] must be called with the pointer returned by [`alloc`].
    pub(crate) fn websocket_new(id: u32, url_ptr: u32, url_len: u32) -> u32;

    /// Close a WebSocket previously initialized with [`websocket_new`].
    ///
    /// This destroys the identifier passed as parameter. This identifier must never be passed
    /// through the FFI boundary, unless the same identifier is later allocated again with
    /// [`websocket_new`].
    ///
    /// The WebSocket connection must be closed in the background. The Rust code isn't interested
    /// in incoming messages from this WebSocket anymore.
    ///
    /// > **Note**: If implemented using the `WebSocket` API, remember to unregister event
    /// >           handlers before calling `WebSocket.close()`.
    pub(crate) fn websocket_close(id: u32);

    /// Queues data on the given WebSocket. The data is found in the memory of the WebAssembly
    /// virtual machine, at the given pointer. The data must be sent as a binary frame.
    ///
    /// The WebSocket must currently be in the `Open` state. See the documentation of
    /// [`websocket_new`] for details.
    pub(crate) fn websocket_send(id: u32, ptr: u32, len: u32);
}

/// Allocates a buffer of the given length, with an alignment of 1.
///
/// This must be used in the context of [`init`].
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> u32 {
    super::alloc(len)
}

/// Initializes the client.
///
/// Use [`alloc`] to allocate either one or two buffers: one for the chain specs, and an optional
/// one for the database content.
/// The buffers **must** have been allocated with [`alloc`]. They are freed when this function is
/// called.
///
/// Write the chain specs and the database content in these two buffers.
///
/// Then, pass the pointer and length of these two buffers to this function.
/// Pass `0` for `database_content_ptr` and `database_content_len` if the database is empty.
#[no_mangle]
pub extern "C" fn init(
    chain_specs_ptr: u32,
    chain_specs_len: u32,
    database_content_ptr: u32,
    database_content_len: u32,
) {
    super::init(
        chain_specs_ptr,
        chain_specs_len,
        database_content_ptr,
        database_content_len,
    );
}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[no_mangle]
pub extern "C" fn timer_finished(timer_id: u32) {
    super::timer_finished(timer_id);
}

/// Called by the JavaScript code if the WebSocket switches to the `Open` state. The WebSocket
/// must be in the `Opening` state.
///
/// Must only be called once per WebSocket object.
///
/// See also [`websocket_open`].
#[no_mangle]
pub extern "C" fn websocket_open(id: u32) {
    super::websocket_open(id);
}

/// Notify of a message being received on the WebSocket. The WebSocket must be in the `Open` state.
///
/// See also [`websocket_open`].
///
/// The buffer **must** have been allocated with [`alloc`]. It is freed when this function is
/// called.
#[no_mangle]
pub extern "C" fn websocket_message(id: u32, ptr: u32, len: u32) {
    super::websocket_message(id, ptr, len)
}

/// Can be called at any point by the JavaScript code if the WebSocket switches to the `Closed`
/// state.
///
/// Must only be called once per WebSocket object.
///
/// See also [`websocket_open`].
#[no_mangle]
pub extern "C" fn websocket_closed(id: u32) {
    super::websocket_closed(id)
}
