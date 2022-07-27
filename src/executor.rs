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

//! WebAssembly runtime code execution.
//!
//! WebAssembly (often abbreviated *Wasm*) plays a big role in Substrate/Polkadot. The storage of
//! each block in the chain has a special key named `:code` which contains the WebAssembly code
//! of what we call *the runtime*.
//!
//! The runtime is a program (in WebAssembly) that decides, amongst other things, whether
//! transactions are valid and how to apply them on the storage, and whether blocks themselves are
//! valid.
//!
//! This module contains everything necessary to execute runtime code. The highest-level
//! sub-module is [`runtime_host`].

mod allocator; // TODO: make public after refactoring
pub mod host;
pub mod read_only_runtime_host;
pub mod runtime_host;
pub mod storage_diff;
pub mod vm;

pub use host::{CoreVersion, CoreVersionError};

/// Default number of heap pages if the storage doesn't specify otherwise.
///
/// # Context
///
/// In order to initialize a [`host::HostVmPrototype`], one needs to pass a certain number of
/// heap pages that are available to the runtime.
///
/// This number is normally found in the storage, at the key `:heappages`. But if it is not
/// specified, then the value of this constant must be used.
pub const DEFAULT_HEAP_PAGES: vm::HeapPages = vm::HeapPages::new(2048);

/// Converts a value of the key `:heappages` found in the storage to an actual number of heap
/// pages.
pub fn storage_heap_pages_to_value(
    storage_value: Option<&[u8]>,
) -> Result<vm::HeapPages, InvalidHeapPagesError> {
    if let Some(storage_value) = storage_value {
        let bytes =
            <[u8; 8]>::try_from(storage_value).map_err(|_| InvalidHeapPagesError::WrongLen)?;
        let num = u64::from_le_bytes(bytes);
        let num = u32::try_from(num).map_err(|_| InvalidHeapPagesError::TooLarge)?;
        Ok(vm::HeapPages::from(num))
    } else {
        Ok(DEFAULT_HEAP_PAGES)
    }
}

/// Error potentially returned by [`storage_heap_pages_to_value`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum InvalidHeapPagesError {
    /// Storage value has the wrong length.
    WrongLen,
    /// Number of heap pages is too large.
    TooLarge,
}
