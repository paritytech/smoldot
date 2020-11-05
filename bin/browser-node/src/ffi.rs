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

#[link_section = "substrate-lite"]
extern {
    /// Must return the number of milliseconds that have passed since the UNIX epoch, ignoring
    /// leap seconds.
    ///
    /// This is typically implemented by calling `Date.now()` and converting the result to an
    /// integer.
    ///
    /// See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now
    fn unix_time_ms() -> u64;

    /// Must return the number of milliseconds that have passed since an arbitrary point in time.
    ///
    /// Contrary to [`unix_time_ms`], the returned value must never be inferior to a value
    /// previously returned. Consequently, this must not be implemented using `Date.now()`, whose
    /// value can decrease if the user adjusts their machine's clock, but rather with
    /// `Performance.now()` or similar.
    ///
    /// See https://developer.mozilla.org/fr/docs/Web/API/Performance/now
    fn monotonic_clock_ms() -> u64;

    /// After `milliseconds` milliseconds have passed, must call [`timer_finished`] with the `id`
    /// passed as parameter.
    ///
    /// When [`timer_finished`] is called, the value of [`monotonic_clock_ms`] must have increased
    /// by the given number of `milliseconds`.
    fn start_timer(id: u32, milliseconds: u64);

    /// Must fill with random values the WebAssembly memory starting at offset `ptr` and of `len`
    /// bytes.
    ///
    /// The randomness must be suitable crytographic purposes. **Do not** use `Math.random()`.
    /// Instead, use [`Crypto.getRandomValues`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues).
    fn fill_random(ptr: u32, len: u32);

    /// Must initialize a new WebSocket connection that tries to connect to the given URL.
    ///
    /// The URL is a UTF-8 string found in the WebAssembly memory at offset `url_ptr` and with
    /// `url_len` bytes. The string is in a format suitable for
    /// [`new WebSocket()`](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket).
    ///
    /// Returns a unique identifier for this connection.
    fn websocket_open(url_ptr: u32, url_len: u32) -> u64;
}

#[no_mangle]
pub extern fn init(chain_specs_ptr: u32, chain_specs_len: u32, database_content_ptr: u32, database_content_len: u32) {

}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[no_mangle]
pub extern fn timer_finished(timer_id: u32) {

}

pub extern fn websocket_open_result(id: u64) {
    
}
