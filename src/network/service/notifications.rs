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

use crate::libp2p::{
    peers::{self, QueueNotificationError},
    PeerId,
};
use crate::network::protocol;
use crate::util;

use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Add, Sub},
    time::Duration,
};

pub use crate::libp2p::{
    collection::{self, ReadWrite},
    peers::{
        ConnectionId, ConnectionToCoordinator, CoordinatorToConnection, InRequestId, InboundError,
        MultiStreamConnectionTask, MultiStreamHandshakeKind, OutRequestId,
        SingleStreamConnectionTask, SingleStreamHandshakeKind,
    },
};

use super::*;

#[derive(Debug, Copy, Clone)]
// TODO: link to some doc about how GrandPa works: what is a round, what is the set id, etc.
pub struct GrandpaState {
    pub round_number: u64,
    /// Set of authorities that will be used by the node to try finalize the children of the block
    /// of [`GrandpaState::commit_finalized_height`].
    pub set_id: u64,
    /// Height of the highest block considered final by the node.
    pub commit_finalized_height: u64,
}

// Update this when a new notifications protocol is added.
pub(super) const NOTIFICATIONS_PROTOCOLS_PER_CHAIN: usize = 3;

pub(super) fn protocols<'a>(
    chains: impl Iterator<Item = &'a ChainConfig>,
) -> Vec<peers::NotificationProtocolConfig> {
    // The order of protocols here is important, as it defines the values of `protocol_index`
    // to pass to libp2p or that libp2p produces.
    chains
        .flat_map(|chain| {
            iter::once(peers::NotificationProtocolConfig {
                protocol_name: format!("/{}/block-announces/1", chain.protocol_id),
                max_handshake_size: 1024 * 1024, // TODO: arbitrary
                max_notification_size: 1024 * 1024,
            })
            .chain(iter::once(peers::NotificationProtocolConfig {
                protocol_name: format!("/{}/transactions/1", chain.protocol_id),
                max_handshake_size: 4,
                max_notification_size: 16 * 1024 * 1024,
            }))
            .chain({
                // The `has_grandpa_protocol` flag controls whether the chain uses GrandPa.
                // Note, however, that GrandPa is technically left enabled (but unused) on all
                // chains, in order to make the rest of the code of this module more
                // comprehensible.
                iter::once(peers::NotificationProtocolConfig {
                    protocol_name: "/paritytech/grandpa/1".to_string(),
                    max_handshake_size: 4,
                    max_notification_size: 1024 * 1024,
                })
            })
        })
        .collect()
}

impl<TNow> ChainNetwork<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Called when the underlying state machine has generated a
    /// [`peers::Event::NotificationsOutResult`].
    pub(super) fn on_notifications_out_result(
        &mut self,
        now: &TNow,
        peer_id: PeerId,
        notifications_protocol_index: usize,
        result: Result<Vec<u8>, collection::NotificationsOutErr>,
    ) -> Option<Event> {
        match result {
            // Successfully opened block announces substream.
            // The block announces substream is the main substream that determines whether
            // a "chain" is open.
            Ok(remote_handshake)
                if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 =>
            {
                let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                // Check validity of the handshake.
                let remote_handshake = match protocol::decode_block_announces_handshake(
                    self.chains[chain_index].chain_config.block_number_bytes,
                    &remote_handshake,
                ) {
                    Ok(hs) => hs,
                    Err(err) => {
                        // TODO: must close the substream and unassigned the slot
                        return Some(Event::ProtocolError {
                            error: ProtocolError::BadBlockAnnouncesHandshake(err),
                            peer_id,
                        });
                    }
                };

                // The desirability of the transactions and grandpa substreams is always equal
                // to whether the block announces substream is open.
                self.inner.set_peer_notifications_out_desired(
                    &peer_id,
                    chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
                    peers::DesiredState::DesiredReset,
                );
                self.inner.set_peer_notifications_out_desired(
                    &peer_id,
                    chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2,
                    peers::DesiredState::DesiredReset,
                );

                let slot_ty = {
                    let local_genesis = self.chains[chain_index].chain_config.genesis_hash;
                    let remote_genesis = *remote_handshake.genesis_hash;

                    if remote_genesis != local_genesis {
                        let unassigned_slot_ty = self.unassign_slot(chain_index, &peer_id).unwrap();

                        return Some(Event::ChainConnectAttemptFailed {
                            peer_id,
                            chain_index,
                            unassigned_slot_ty,
                            error: NotificationsOutErr::GenesisMismatch {
                                local_genesis,
                                remote_genesis,
                            },
                        });
                    }

                    // Update the k-buckets to mark the peer as connected.
                    // Note that this is done after having made sure that the handshake
                    // was correct.
                    // TODO: should we not insert the entry in the k-buckets as well? seems important for incoming connections
                    if let Some(mut entry) = self.chains[chain_index]
                        .kbuckets
                        .entry(&peer_id)
                        .into_occupied()
                    {
                        entry.set_state(&now, kademlia::kbuckets::PeerState::Connected);
                    }

                    if self.chains[chain_index].in_peers.contains(&peer_id) {
                        SlotTy::Inbound
                    } else {
                        debug_assert!(self.chains[chain_index].out_peers.contains(&peer_id));
                        SlotTy::Outbound
                    }
                };

                let _was_inserted = self.open_chains.insert((peer_id.clone(), chain_index));
                debug_assert!(_was_inserted);

                let best_hash = *remote_handshake.best_hash;
                let best_number = remote_handshake.best_number;
                let role = remote_handshake.role;

                Some(Event::ChainConnected {
                    peer_id,
                    chain_index,
                    slot_ty,
                    best_hash,
                    best_number,
                    role,
                })
            }

            // Successfully opened transactions substream.
            Ok(_) if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1 => {
                // Nothing to do.
                None
            }

            // Successfully opened Grandpa substream.
            // Need to send a Grandpa neighbor packet in response.
            Ok(_) if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2 => {
                let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                let notification = {
                    let grandpa_config = *self.chains[chain_index]
                        .chain_config
                        .grandpa_protocol_config
                        .as_ref()
                        .unwrap();

                    protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
                        round_number: grandpa_config.round_number,
                        set_id: grandpa_config.set_id,
                        commit_finalized_height: grandpa_config.commit_finalized_height,
                    })
                    .scale_encoding(self.chains[chain_index].chain_config.block_number_bytes)
                    .fold(Vec::new(), |mut a, b| {
                        a.extend_from_slice(b.as_ref());
                        a
                    })
                };

                let _ = self.inner.queue_notification(
                    &peer_id,
                    notifications_protocol_index,
                    notification.clone(),
                );

                None
            }

            // Failed to open block announces substream.
            Err(error) if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 => {
                let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

                let unassigned_slot_ty = self.unassign_slot(chain_index, &peer_id).unwrap();

                Some(Event::ChainConnectAttemptFailed {
                    peer_id,
                    chain_index,
                    unassigned_slot_ty,
                    error: NotificationsOutErr::Substream(error),
                })
            }

            // Other protocol.
            Err(_) => None,

            // Unrecognized protocol.
            Ok(_) => unreachable!(),
        }
    }

    /// Called when the underlying state machine has generated a
    /// [`peers::Event::NotificationsOutClose`].
    pub(super) fn on_notifications_out_close(
        &mut self,
        now: &TNow,
        peer_id: PeerId,
        notifications_protocol_index: usize,
    ) -> Option<Event> {
        if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // The desirability of the transactions and grandpa substreams is always equal
            // to whether the block announces substream is open.
            //
            // These two calls modify `self.inner`, but they are still cancellation-safe
            // as they can be repeated multiple times.
            self.inner.set_peer_notifications_out_desired(
                &peer_id,
                chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
                peers::DesiredState::NotDesired,
            );
            self.inner.set_peer_notifications_out_desired(
                &peer_id,
                chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2,
                peers::DesiredState::NotDesired,
            );

            // The chain is now considered as closed.
            // TODO: can was_open ever be false?
            let was_open = self.open_chains.remove(&(peer_id.clone(), chain_index)); // TODO: cloning :(

            if was_open {
                // Update the k-buckets, marking the peer as disconnected.
                let unassigned_slot_ty = {
                    let unassigned_slot_ty = self.unassign_slot(chain_index, &peer_id).unwrap();

                    if let Some(mut entry) = self.chains[chain_index]
                        .kbuckets
                        .entry(&peer_id)
                        .into_occupied()
                    {
                        // Note that the state might have already be `Disconnected`, which
                        // can happen for example in case of a problem in the handshake
                        // sent back by the remote.
                        entry.set_state(&now, kademlia::kbuckets::PeerState::Disconnected);
                    }

                    unassigned_slot_ty
                };

                return Some(Event::ChainDisconnected {
                    chain_index,
                    peer_id,
                    unassigned_slot_ty,
                });
            }

            None
        } else {
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // The state of notification substreams other than block announces must
            // always match the state of the block announces.
            // Therefore, if the peer is considered open, try to reopen the substream that
            // has just been closed.
            // TODO: cloning of peer_id :-/
            if self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                self.inner.set_peer_notifications_out_desired(
                    &peer_id,
                    notifications_protocol_index,
                    peers::DesiredState::DesiredReset,
                );
            }

            None
        }
    }

    /// Called when the underlying state machine has generated a
    /// [`peers::Event::NotificationsInOpen`].
    pub(super) fn on_notifications_in_open(
        &mut self,
        substream_id: peers::SubstreamId,
        peer_id: PeerId,
        notifications_protocol_index: usize,
        handshake: Vec<u8>,
    ) -> Option<Event> {
        if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 0 {
            // Remote wants to open a block announces substream.
            // The block announces substream is the main substream that determines whether
            // a "chain" is open.
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // Immediately reject the substream if the handshake fails to parse.
            if let Err(err) = protocol::decode_block_announces_handshake(
                self.chains[chain_index].chain_config.block_number_bytes,
                &handshake,
            ) {
                self.inner.in_notification_refuse(substream_id);

                return Some(Event::ProtocolError {
                    error: ProtocolError::BadBlockAnnouncesHandshake(err),
                    peer_id,
                });
            }

            // If the peer doesn't already have an outbound slot, check whether we can
            // allocate an inbound slot for it.
            let has_out_slot = self.chains[chain_index].out_peers.contains(&peer_id);
            if !has_out_slot
                && self.chains[chain_index].in_peers.len()
                    >= usize::try_from(self.chains[chain_index].chain_config.in_slots)
                        .unwrap_or(usize::max_value())
            {
                // All in slots are occupied. Refuse the substream.
                self.inner.in_notification_refuse(substream_id);
                return None;
            }

            // At this point, accept the node can no longer fail.

            // Generate the handshake to send back.
            let handshake = {
                let chain_config = &self.chains[chain_index].chain_config;
                protocol::encode_block_announces_handshake(
                    protocol::BlockAnnouncesHandshakeRef {
                        best_hash: &chain_config.best_hash,
                        best_number: chain_config.best_number,
                        genesis_hash: &chain_config.genesis_hash,
                        role: chain_config.role,
                    },
                    chain_config.block_number_bytes,
                )
                .fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                })
            };

            self.inner.in_notification_accept(substream_id, handshake);

            if !has_out_slot {
                // TODO: future cancellation issue; if this future is cancelled, then trying to do the `in_notification_accept` again next time will panic
                self.inner.set_peer_notifications_out_desired(
                    &peer_id,
                    notifications_protocol_index,
                    peers::DesiredState::DesiredReset,
                );

                // The state modification is done at the very end, to not have any
                // future cancellation issue.
                let _was_inserted = self.chains[chain_index].in_peers.insert(peer_id.clone());
                debug_assert!(_was_inserted);

                return Some(Event::InboundSlotAssigned {
                    chain_index,
                    peer_id,
                });
            }
        } else if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 1 {
            // Remote wants to open a transactions substream.
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // Accept the substream only if the peer is "chain connected".
            if self
                .open_chains // TODO: clone :-/
                .contains(&(peer_id.clone(), chain_index))
            {
                self.inner.in_notification_accept(substream_id, Vec::new());
            } else {
                self.inner.in_notification_refuse(substream_id);
            }
        } else if (notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN) == 2 {
            // Remote wants to open a grandpa substream.
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // Reject the substream if the this peer isn't "chain connected".
            if !self
                .open_chains // TODO: clone :-/
                .contains(&(peer_id.clone(), chain_index))
            {
                self.inner.in_notification_refuse(substream_id);
                return None;
            }

            // Peer is indeed connected. Accept the substream.

            // Build the handshake to send back.
            let handshake = {
                self.chains[chain_index]
                    .chain_config
                    .role
                    .scale_encoding()
                    .to_vec()
            };

            self.inner.in_notification_accept(substream_id, handshake);
        } else {
            // Unrecognized notifications protocol.
            unreachable!();
        }

        None
    }

    /// Called when the underlying state machine has generated a
    /// [`peers::Event::NotificationsInClose`].
    pub(super) fn on_notifications_in_close(
        &mut self,
        peer_id: PeerId,
        notifications_protocol_index: usize,
    ) -> Option<Event> {
        if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
            // Remote closes a block announce substream.
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // We unassign the inbound slot of the peer if it had one.
            // If the peer had an outbound slot, then this does nothing.
            if self.chains[chain_index].in_peers.remove(&peer_id) {
                self.inner.set_peer_notifications_out_desired(
                    &peer_id,
                    notifications_protocol_index,
                    peers::DesiredState::NotDesired,
                );
            }
        }

        None
    }

    /// Called when the underlying state machine has generated a
    /// [`peers::Event::NotificationsInOpenCancel`].
    pub(super) fn on_notifications_in_open_cancel(
        &mut self,
        _id: peers::SubstreamId,
    ) -> Option<Event> {
        // Because we always accept/refuse incoming notification substreams instantly,
        // there's no possibility for a cancellation to happen.
        unreachable!()
    }

    /// Called when the underlying state machine has generated a [`peers::Event::NotificationsIn`].
    pub(super) fn on_notification_in(
        &mut self,
        peer_id: PeerId,
        notifications_protocol_index: usize,
        notification: Vec<u8>,
    ) -> Option<Event> {
        if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 0 {
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // Don't report events about nodes we don't have an outbound substream with.
            // TODO: think about possible race conditions regarding missing block
            // announcements, as the remote will think we know it's at a certain block
            // while we ignored its announcement ; it isn't problematic as long as blocks
            // are generated continuously, as announcements will be generated periodically
            // as well and the state will no longer mismatch
            // TODO: cloning of peer_id :(
            if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                return None;
            }

            let block_number_bytes = self.chains[chain_index].chain_config.block_number_bytes;

            // Check the format of the block announce.
            if let Err(err) = protocol::decode_block_announce(&notification, block_number_bytes) {
                return Some(Event::ProtocolError {
                    error: ProtocolError::BadBlockAnnounce(err),
                    peer_id,
                });
            }

            Some(Event::BlockAnnounce {
                chain_index,
                peer_id,
                announce: EncodedBlockAnnounce {
                    message: notification,
                    block_number_bytes,
                },
            })
        } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 1 {
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;

            // Don't report events about nodes we don't have an outbound substream with.
            // TODO: cloning of peer_id :(
            if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                return None;
            }

            // TODO: this is unimplemented
            None
        } else if notifications_protocol_index % NOTIFICATIONS_PROTOCOLS_PER_CHAIN == 2 {
            let chain_index = notifications_protocol_index / NOTIFICATIONS_PROTOCOLS_PER_CHAIN;
            let block_number_bytes = self.chains[chain_index].chain_config.block_number_bytes;

            // Don't report events about nodes we don't have an outbound substream with.
            // TODO: cloning of peer_id :(
            if !self.open_chains.contains(&(peer_id.clone(), chain_index)) {
                return None;
            }

            let decoded_notif =
                match protocol::decode_grandpa_notification(&notification, block_number_bytes) {
                    Ok(n) => n,
                    Err(err) => {
                        return Some(Event::ProtocolError {
                            error: ProtocolError::BadGrandpaNotification(err),
                            peer_id,
                        })
                    }
                };

            // Commit messages are the only type of message that is important for
            // light clients. Anything else is presently ignored.
            if let protocol::GrandpaNotificationRef::Commit(_) = decoded_notif {
                Some(Event::GrandpaCommitMessage {
                    chain_index,
                    peer_id,
                    message: EncodedGrandpaCommitMessage {
                        message: notification,
                        block_number_bytes,
                    },
                })
            } else {
                None
            }
        } else {
            // Unrecognized notifications protocol.
            unreachable!();
        }
    }

    /// Modifies the best block of the local node. See [`ChainConfig::best_hash`] and
    /// [`ChainConfig::best_number`].
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range.
    ///
    pub fn set_local_best_block(
        &mut self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        let mut config = &mut self.chains[chain_index].chain_config;
        config.best_hash = best_hash;
        config.best_number = best_number;
    }

    /// Update the state of the local node with regards to GrandPa rounds.
    ///
    /// Calling this method does two things:
    ///
    /// - Send on all the active GrandPa substreams a "neighbor packet" indicating the state of
    ///   the local node.
    /// - Update the neighbor packet that is automatically sent to peers when a GrandPa substream
    ///   gets opened.
    ///
    /// In other words, calling this function atomically informs all the present and future peers
    /// of the state of the local node regarding the GrandPa protocol.
    ///
    /// > **Note**: The information passed as parameter isn't validated in any way by this method.
    ///
    /// This function might generate a message destined to connections. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process these messages after it has
    /// returned.
    ///
    /// # Panic
    ///
    /// Panics if `chain_index` is out of range, or if the chain has GrandPa disabled.
    ///
    pub fn set_local_grandpa_state(&mut self, chain_index: usize, grandpa_state: GrandpaState) {
        // Bytes of the neighbor packet to send out.
        let packet = protocol::GrandpaNotificationRef::Neighbor(protocol::NeighborPacket {
            round_number: grandpa_state.round_number,
            set_id: grandpa_state.set_id,
            commit_finalized_height: grandpa_state.commit_finalized_height,
        })
        .scale_encoding(self.chains[chain_index].chain_config.block_number_bytes)
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        // Now sending out.
        let _ = self
            .inner
            .broadcast_notification(chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 2, packet);

        // Update the locally-stored state, but only after the notification has been broadcasted.
        // This way, if the user cancels the future while `broadcast_notification` is executing,
        // the whole operation is cancelled.
        *self.chains[chain_index]
            .chain_config
            .grandpa_protocol_config
            .as_mut()
            .unwrap() = grandpa_state;
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: there this extra parameter in block announces that is unused on many chains but not always
    pub fn send_block_announce(
        &mut self,
        target: &PeerId,
        chain_index: usize,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let buffers_to_send = protocol::encode_block_announce(protocol::BlockAnnounceRef {
            scale_encoded_header,
            is_best,
        });

        let notification = buffers_to_send.fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        self.inner.queue_notification(
            target,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN,
            notification,
        )
    }

    /// Returns `true` if it is allowed to call [`ChainNetwork::send_block_announce`], in other
    /// words if there is an outbound block announces substream currently open with the target.
    ///
    /// If this function returns `false`, calling [`ChainNetwork::send_block_announce`] will
    /// panic.
    pub fn can_send_block_announces(&self, target: &PeerId, chain_index: usize) -> bool {
        self.inner
            .can_queue_notification(target, chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN)
    }

    /// Returns the list of peers for which we have a fully established notifications protocol of
    /// the given protocol.
    pub fn opened_transactions_substream(
        &'_ self,
        chain_index: usize,
    ) -> impl Iterator<Item = &'_ PeerId> + '_ {
        self.inner
            .opened_out_notifications(chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1)
    }

    ///
    ///
    /// Must be passed the SCALE-encoded transaction.
    ///
    /// This function might generate a message destined connections. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: -> broadcast_transaction
    pub fn announce_transaction(
        &mut self,
        target: &PeerId,
        chain_index: usize,
        extrinsic: &[u8],
    ) -> Result<(), QueueNotificationError> {
        let mut val = Vec::with_capacity(1 + extrinsic.len());
        val.extend_from_slice(util::encode_scale_compact_usize(1).as_ref());
        val.extend_from_slice(extrinsic);
        self.inner.queue_notification(
            target,
            chain_index * NOTIFICATIONS_PROTOCOLS_PER_CHAIN + 1,
            val,
        )
    }
}

/// Error that can happen when trying to open an outbound notifications substream.
#[derive(Debug, Clone, derive_more::Display)]
pub enum NotificationsOutErr {
    /// Error in the underlying protocol.
    #[display(fmt = "{}", _0)]
    Substream(peers::NotificationsOutErr),
    /// Mismatch between the genesis hash of the remote and the local genesis hash.
    #[display(fmt = "Mismatch between the genesis hash of the remote and the local genesis hash")]
    GenesisMismatch {
        /// Hash of the genesis block of the chain according to the local node.
        local_genesis: [u8; 32],
        /// Hash of the genesis block of the chain according to the remote node.
        remote_genesis: [u8; 32],
    },
}

/// Undecoded but valid block announce handshake.
pub struct EncodedBlockAnnounceHandshake {
    handshake: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedBlockAnnounceHandshake {
    /// Returns the decoded version of the handshake.
    pub fn decode(&self) -> protocol::BlockAnnouncesHandshakeRef {
        protocol::decode_block_announces_handshake(self.block_number_bytes, &self.handshake)
            .unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounceHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid block announce.
#[derive(Clone)]
pub struct EncodedBlockAnnounce {
    message: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedBlockAnnounce {
    /// Returns the decoded version of the announcement.
    pub fn decode(&self) -> protocol::BlockAnnounceRef {
        protocol::decode_block_announce(&self.message, self.block_number_bytes).unwrap()
    }
}

impl fmt::Debug for EncodedBlockAnnounce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid GrandPa commit message.
#[derive(Clone)]
pub struct EncodedGrandpaCommitMessage {
    message: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedGrandpaCommitMessage {
    /// Returns the encoded bytes of the commit message.
    pub fn into_encoded(mut self) -> Vec<u8> {
        // Skip the first byte because `self.message` is a `GrandpaNotificationRef`.
        self.message.remove(0);
        self.message
    }

    /// Returns the encoded bytes of the commit message.
    pub fn as_encoded(&self) -> &[u8] {
        // Skip the first byte because `self.message` is a `GrandpaNotificationRef`.
        &self.message[1..]
    }

    /// Returns the decoded version of the commit message.
    pub fn decode(&self) -> protocol::CommitMessageRef {
        match protocol::decode_grandpa_notification(&self.message, self.block_number_bytes) {
            Ok(protocol::GrandpaNotificationRef::Commit(msg)) => msg,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for EncodedGrandpaCommitMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}
