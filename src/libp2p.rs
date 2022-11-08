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

//! Low-level peer-to-peer networking.
//!
//! The peer-to-peer networking protocol used by Substrate-based chains is called *libp2p*. Its
//! specifications can be found in the <https://github.com/libp2p/specs> repository. This module
//! contains code that allows connecting to libp2p-compatible nodes. All the logic specific to
//! Substrate/Polkadot isn't handled here and is instead done in the [`crate::network`] module.
//!
//! # Network identity
//!
//! In order to join the peer-to-peer network, one must first generate a *network identity*. A
//! network identity is a small struct containing a cryptographic public key (typically Ed25519,
//! but other algorithms might be used) or the hash of a cryptographic public key. A network
//! identity is represented with the [`PeerId`] struct.
//!
//! Network identities primarily have a binary encoding. When displayed for UI purposes, the
//! string representation, which consists in the Base58 encoding of the binary encoding, is used.
//! Example string representation: `12D3KooWR3UGwwSP5wdBMk2JXXuzXoscPSudv8hmQkzfZTBzSbeE`.
//!
//! In order to generate a network identity, fill a [`peer_id::PublicKey::Ed25519`] with an
//! Ed25519 public key, then use [`PeerId::from_public_key`].
//!
//! When establishing a connection to another member the peer-to-peer network, a Diffie-Hellman
//! handshake is performed in order to ensure that the remote indeed possesses the private key
//! corresponding to its network identity.
//!
//! See also the documentation of [`peer_id`] for more information.
//!
//! # The `ReadWrite` object
//!
//! One of the most important objects in this module is the [`read_write::ReadWrite`] struct.
//!
//! In order to allow for better determinism and testability, absolutely no code in this module
//! directly interacts with operating-system-provided TCP sockets. Instead, this modules provides
//! state machines that need to be synchronized manually with a [`read_write::ReadWrite`] through
//! function calls. Once synchronized, the API user must in turn manually synchronize this
//! [`read_write::ReadWrite`] with the actual state of the operating-system-provided TCP socket.
//!
//! The [`read_write::ReadWrite`] struct notably contains data that has been received on the
//! socket but hasn't been processed yet, and data that has been queued for sending out but hasn't
//! been sent yet.
//!
//! See also the documentation of [`read_write`] for more information.
//!
//! # State machine
//!
//! The main object of this module is the [`peers::Peers`]. It is a state machine which, in
//! summary, contains:
//!
//! - A list of handshaking and established connections, that the API user must manually
//! synchronize by calling [`collection::SingleStreamConnectionTask::read_write`],
//! [`collection::SingleStreamConnectionTask::reset`],
//! [`collection::MultiStreamConnectionTask::substream_read_write`],
//! [`collection::MultiStreamConnectionTask::reset`],
//! [`collection::MultiStreamConnectionTask::add_substream`], and/or
//! [`collection::MultiStreamConnectionTask::desired_outbound_substreams`]. When
//! inserting a new outgoing connection, the API user can specify which [`PeerId`] this connection
//! is expected to reach.
//! - A list of [`̀PeerId`]s that have been marked by the API user as desired. The [`peers::Peers`]
//! is then able to provide the list of [`PeerId`]s that have been marked as desired but that no
//! existing connection reaches or tries to reach.
//! - A list of events that happen on the set of peer-to-peer connections, and that can be
//! retrieved one by one by calling [`peers::Peers::next_event`].
//!
//! It is the responsibility of the API user to grab the list of unfulfilled [`̀PeerId`]s and
//! insert new connections that are expected to reach these unfulfilled [`PeerId`]s. To do so,
//! one must run a certain discovery mechanism in order to find out the addresses that will
//! permit to reach peers. This is out of scope of this module.
//!
//! It is also the responsibility of the API user to call [`peers::Peers::next_event`] in order to
//! react to the activity on the various connections, and user the various other methods of the
//! [`peers::Peers`] state machine, such as for example [`peers::Peers::start_request`], to
//! interact with the remotes.
//!
//! See also the documentation of [`peers`] for more information.
//!

pub mod async_std_connection;
pub mod collection;
pub mod connection;
pub mod multiaddr;
pub mod multihash;
pub mod peer_id;
pub mod peers;
pub mod read_write;
pub mod websocket;

pub use multiaddr::Multiaddr;
pub use peer_id::PeerId;
