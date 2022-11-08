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

//! Syncing, short for synchronizing, consists in synchronizing the state of a local chain with
//! the state of the chain contained in other machines, called *remotes* or *sources*.
//!
//! > **Note**: While the above summary is a bit abstract, in practice it is almost always
//! >           done by exchanging messages through a peer-to-peer network.
//!
//! Multiple strategies exist for syncing, one for each sub-module, and which one to employ
//! depends on the amount of information that is desired (e.g. is it required to know the header
//! and/or body of every single block, or can some blocks be skipped?) and the distance between
//! the highest block of the local chain and the highest block available on the remotes.
//!
//! The [`all`] module represents a good combination of all syncing strategies and should be the
//! default choice for most clients.
//!
//! # Security considerations
//!
//! ## Eclipse attacks
//!
//! While there exists various trade-offs between syncing strategies, safety is never part of
//! these trade-offs. All syncing strategies are safe, in the sense that malicious remotes cannot
//! corrupt the state of the local chain.
//!
//! It is possible, however, for a malicious remote to omit some information, such as the
//! existence of a specific block. If all the remotes that are being synchronized from are
//! malicious and collude to omit the same information, there is no way for the local node to
//! learn this information or even to be aware that it is missing an information. This is called
//! an **eclipse attack**.
//!
//! For this reason, it is important to ensure a large number and a good distribution of the
//! sources. In the context of a peer-to-peer network where machines are picked randomly, a
//! minimum threshold of around 7 peers is generally considered acceptable. Similarly, in the
//! context of a peer-to-peer network, it is important to establish outgoing connections to other
//! nodes and not only rely on incoming connections, as there is otherwise the possibility of a
//! single actor controlling all said incoming connections.
//!
//! ## Malicious runtimes
//!
//! Synchronizing the chain requires executing a piece of WebAssembly code known as the runtime.
//! Each chain has a different runtime, stored on chain, and this runtime can be modified as part
//! of a the transactions in a block.
//!
//! There are two safety considerations concerning executing runtime code:
//!
//! - The execution could take a lot of time, or possibly be stuck in an infinite loop.
//! - The execution could modify a lot of storage items. Smoldot needs to store every single
//! storage item change, and a lot of modification could make the memory usage of smoldot explode.
//!
//! The Substrate model, and thus the smoldot implementation, intentionally do not do anything to
//! address these two safety issues. In other words, the runtime of a chain is considered to never
//! be malicious. After all, a chain whose runtime is intentionally trying to crash a client is
//! borked and there is no reason to connect to it.
//!

pub mod all;
pub mod all_forks;
pub mod optimistic;
pub mod para;
pub mod warp_sync;
