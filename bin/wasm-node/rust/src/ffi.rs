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
    /// This is typically implemented by calling `Date.now()` and converting the result to an
    /// integer.
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
    /// Returns a unique identifier for this connection.
    pub(crate) fn websocket_open(url_ptr: u32, url_len: u32) -> u64;
}

/// Allocates a buffer of the given length, with an alignment of 1.
///
/// This must be used in the context of [`init`].
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
    let chain_specs_ptr = usize::try_from(chain_specs_ptr).unwrap();
    let chain_specs_len = usize::try_from(chain_specs_len).unwrap();
    let database_content_ptr = usize::try_from(database_content_ptr).unwrap();
    let database_content_len = usize::try_from(database_content_len).unwrap();

    let chain_specs: Box<[u8]> = unsafe {
        Box::from_raw(slice::from_raw_parts_mut(
            chain_specs_ptr as *mut u8,
            chain_specs_len,
        ))
    };

    // TODO: don't unwrap
    let chain_specs = String::from_utf8(Vec::from(chain_specs)).unwrap();

    let database_content = if database_content_ptr != 0 {
        Some(unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                database_content_ptr as *mut u8,
                database_content_len,
            ))
        })
    } else {
        None
    };

    super::spawn_task(super::start_client(chain_specs));
}

/// Must be called in response to [`start_timer`] after the given duration has passed.
#[no_mangle]
pub extern "C" fn timer_finished(timer_id: u32) {
    let callback = {
        let ptr = timer_id as *mut Box<dyn FnOnce()>;
        unsafe { Box::from_raw(ptr) }
    };

    callback();
}

pub(super) fn start_timer_wrap(duration: Duration, closure: impl FnOnce()) {
    let callback: Box<Box<dyn FnOnce()>> = Box::new(Box::new(closure));
    let timer_id = u32::try_from(Box::into_raw(callback) as usize).unwrap();
    let milliseconds = u64::try_from(duration.as_millis())
        .unwrap_or(u64::max_value())
        .saturating_add(1);
    unsafe { start_timer(timer_id, milliseconds as f64) }
}

pub extern "C" fn websocket_open_result(id: u64) {}
