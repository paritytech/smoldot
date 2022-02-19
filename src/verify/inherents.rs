// Smoldot
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

//! Inherents, together with transactions, form the body of a block.
//!
//! The body of a block consists of a list of what is called extrinsics. An extrinsic can be
//! either a transaction, when it was submitted by a user, or an inherent, which is what this
//! module is about.
//!
//! When a block is authored, one of the first steps is for the block author to generate the list
//! of inherents. This is done by calling a runtime function, passing as parameter an encoded
//! [`InherentData`].
//!
//! When a block is later verified, the inherents are verified by calling a runtime function and
//! passing as parameter an encoded [`InherentData`] as well.

/// Values of the inherents to pass to the runtime.
#[derive(Debug)]
pub struct InherentData {
    /// Number of milliseconds since the UNIX epoch when the block is generated, ignoring leap
    /// seconds.
    ///
    /// Its identifier passed to the runtime is: `timstap0`.
    pub timestamp: u64,

    /// Consensus-specific fields.
    pub consensus: InherentDataConsensus,
    // TODO: figure out uncles
    /*/// List of valid block headers that have the same height as the parent of the one being
    /// generated.
    ///
    /// Its identifier passed to the runtime is: `uncles00`.
    ///
    /// `TUnc` must be an iterator yielding SCALE-encoded headers.
    pub uncles: TUnc,*/

    // TODO: parachain-related inherents are missing
}

impl InherentData {
    /// Turns this list of inherents into a list that can be passed as parameter to the runtime.
    pub fn as_raw_list(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone + '_)> + Clone + '_ {
        // Note: we use `IntoIter::new` because of a Rust backwards compatibility issue.
        // See https://doc.rust-lang.org/std/primitive.array.html#editions
        core::array::IntoIter::new([
            (*b"timstap0", self.timestamp.to_le_bytes()),
            match self.consensus {
                InherentDataConsensus::Aura { slot_number } => {
                    (*b"auraslot", slot_number.to_le_bytes())
                }
                InherentDataConsensus::Babe { slot_number } => {
                    (*b"babeslot", slot_number.to_le_bytes())
                }
            },
        ])
    }
}

/// Extra consensus-specific items in [`InherentData`].
#[derive(Debug)]
pub enum InherentDataConsensus {
    /// Aura-specific items.
    Aura {
        /// Number of the Aura slot being claimed to generate this block.
        ///
        /// Its identifier passed to the runtime is: `auraslot`.
        slot_number: u64,
    },

    /// Babe-specific items.
    Babe {
        /// Number of the Babe slot being claimed to generate this block.
        ///
        /// Its identifier passed to the runtime is: `babeslot`.
        slot_number: u64,
    },
}
