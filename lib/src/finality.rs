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

//! Finality consists is declaring a block as irreversible. It is now forever part of the chain.
//!
//! There exists two types of finality proofs: Grandpa commits, and Grandpa justifications. These
//! two finality proofs are very similar to each other.
//!
//! In order to be verified, both Grandpa commits and Grandpa justifications require that the
//! verifier knows about specific block headers. Grandpa justifications directly include these
//! block headers in its data, while Grandpa commits are sent in a context where it is assumed
//! that they are known by the node.

pub mod decode;
pub mod encode;
pub mod verify;
