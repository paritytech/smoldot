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

use super::multiaddr;

/// List of potential addresses of a single peer, reachable or not.
pub(super) struct Addresses {
    list: Vec<(multiaddr::Multiaddr, State)>,
}

impl Addresses {
    pub(super) fn new() -> Self {
        Addresses { list: Vec::new() }
    }

    pub(super) fn with_capacity(cap: usize) -> Self {
        Addresses {
            list: Vec::with_capacity(cap),
        }
    }

    pub(super) fn insert_discovered(&mut self, addr: multiaddr::Multiaddr) {
        if self.list.iter().any(|(a, _)| *a == addr) {
            return;
        }

        // TODO: add a cap to the number of addresses?

        self.list.push((addr, State::NotTried));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "pending". Returns `None` if no such address is available.
    pub(super) fn addr_to_pending(&mut self) -> Option<multiaddr::Multiaddr> {
        todo!()
    }
}

enum State {
    /// Currently connected to this address.
    Connected,
    /// Currently trying to connect to this address.
    PendingConnect,
    /// Not currently connected to this address, but address was reached in the past.
    DisconnectedReachable,
    /// Address has been discovered, but its reachability hasn't been tried yet.
    NotTried,
}
