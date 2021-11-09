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

use alloc::vec::Vec;
use core::fmt;

/// List of potential addresses of a single peer, reachable or not.
pub(super) struct Addresses {
    list: Vec<(multiaddr::Multiaddr, State)>,
}

impl Addresses {
    /// Creates a new empty list of addresses with the given capacity pre-allocated.
    pub(super) fn with_capacity(cap: usize) -> Self {
        Addresses {
            list: Vec::with_capacity(cap),
        }
    }

    /// Returns the number of addresses.
    pub(super) fn len(&self) -> usize {
        self.list.len()
    }

    /// Returns the list of addresses stored in this list that are marked as connected.
    pub(super) fn iter_connected(&'_ self) -> impl Iterator<Item = &'_ multiaddr::Multiaddr> + '_ {
        self.list
            .iter()
            .filter(|(_, s)| matches!(s, State::Connected))
            .map(|(a, _)| a)
    }

    /// Inserts a new address in the list in the "not tried" state.
    pub(super) fn insert_discovered(&mut self, addr: multiaddr::Multiaddr) {
        if self.list.iter().any(|(a, _)| *a == addr) {
            return;
        }

        self.list.push((addr, State::NotTried));
    }

    /// If the given address is in the list, removes it.
    ///
    /// Returns whether the value was present.
    pub(super) fn remove(&mut self, addr: &multiaddr::Multiaddr) -> bool {
        if let Some(index) = self.list.iter().position(|(a, _)| a == addr) {
            self.list.remove(index);
            true
        } else {
            false
        }
    }

    /// Returns `true` if the list of addresses is empty.
    ///
    /// > **Note**: This is not the same as the list of addresses containing only disconnected
    /// >           addresses.
    pub(super) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// If the given address is in the list, sets its state to "connected".
    ///
    /// # Panic
    ///
    /// Panics if the state of this address was already connected.
    ///
    pub(super) fn set_connected(&mut self, addr: &multiaddr::Multiaddr) {
        if let Some(index) = self.list.iter().position(|(a, _)| a == addr) {
            assert!(!matches!(self.list[index].1, State::Connected));
            self.list[index].1 = State::Connected;
        }
    }

    /// If the given address is in the list, sets its state to "disconnected".
    ///
    /// # Panic
    ///
    /// Panics if the state of this address was not connected or pending.
    ///
    pub(super) fn set_disconnected(&mut self, addr: &multiaddr::Multiaddr) {
        if let Some(index) = self.list.iter().position(|(a, _)| a == addr) {
            assert!(matches!(
                self.list[index].1,
                State::Connected | State::PendingConnect
            ));

            self.list[index].1 = State::DisconnectedReachable;
        }
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "pending". Returns `None` if no such address is available.
    pub(super) fn addr_to_pending(&mut self) -> Option<&multiaddr::Multiaddr> {
        let index = self
            .list
            .iter()
            .position(|(_, s)| matches!(s, State::DisconnectedReachable | State::NotTried))?;
        self.list[index].1 = State::PendingConnect;
        Some(&self.list[index].0)
    }
}

impl fmt::Debug for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.list.iter()).finish()
    }
}

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use crate::network::Multiaddr;

    #[test]
    fn transition_not_tried_connected() {
        let mut addresses = super::Addresses::new();
        assert!(addresses.is_empty());

        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/5".parse().unwrap();
        addresses.insert_discovered(addr.clone());

        addresses.set_connected(&addr);
        assert!(addresses.addr_to_pending().is_none());

        addresses.set_disconnected(&addr);
    }

    #[test]
    fn transition_not_tried_pending_connected() {
        let mut addresses = super::Addresses::new();
        assert!(addresses.is_empty());

        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/5".parse().unwrap();
        addresses.insert_discovered(addr.clone());

        assert_eq!(addresses.addr_to_pending(), Some(&addr));
        assert!(addresses.addr_to_pending().is_none());

        addresses.set_connected(&addr);

        addresses.set_disconnected(&addr);
    }

    #[test]
    #[should_panic]
    fn transition_not_tried_disconnected() {
        let mut addresses = super::Addresses::new();

        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/5".parse().unwrap();
        addresses.insert_discovered(addr.clone());

        addresses.set_disconnected(&addr);
    }

    #[test]
    #[should_panic]
    fn transition_connected_twice() {
        let mut addresses = super::Addresses::new();

        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/5".parse().unwrap();
        addresses.insert_discovered(addr.clone());

        addresses.set_connected(&addr);
        addresses.set_connected(&addr);
    }
}
