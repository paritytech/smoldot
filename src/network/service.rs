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

//! Networking service. Handles a collection of libp2p TCP connections.
//!
//! # Usage
//!
//! The main data structure in this module is [`Network`], which holds the state of all active
//! and pending libp2p connections to other nodes. The second most important data structure is
//! [`Connection`], which holds the state of a single active connection.
//!
//! The [`Network`] requires [`Connection`] to be spawned. The [`Network`] only holds the latest
//! known state of the various [`Connection`]s associated to it. The state of the [`Network`] and
//! its [`Connection`] isn't performed automatically, and must be performed by the user by
//! exchanging [`ConnectionToService`] and [`ServiceToConnection`] messages between the two.
//!
//! This separation between [`Network`] and [`Connection`] makes it possible to call
//! [`Connection::read_write`] in parallel for multiple different connections. Only the
//! synchronization with the [`Network`] needs to be single-threaded.
