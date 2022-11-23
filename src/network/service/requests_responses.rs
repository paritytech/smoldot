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

use crate::header;
use crate::libp2p::{
    multiaddr, peer_id,
    peers::{self, ConfigRequestResponse},
    PeerId,
};
use crate::network::{kademlia, protocol};

use super::*;

use alloc::{format, vec::Vec};
use core::{
    fmt,
    hash::Hash,
    iter,
    num::NonZeroUsize,
    ops::{Add, Sub},
    time::Duration,
};

pub use crate::libp2p::{
    collection::ReadWrite,
    peers::{
        ConnectionId, ConnectionToCoordinator, CoordinatorToConnection, InRequestId, InboundError,
        MultiStreamConnectionTask, MultiStreamHandshakeKind, OutRequestId,
        SingleStreamConnectionTask, SingleStreamHandshakeKind,
    },
};

/// Identifier for a Kademlia iterative query.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KademliaOperationId(pub(super) u64);

// Update this when a new request response protocol is added.
pub(super) const REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN: usize = 5;

pub(super) fn protocols<'a>(
    chains: impl Iterator<Item = &'a ChainConfig>,
) -> Vec<ConfigRequestResponse> {
    // The order of protocols here is important, as it defines the values of `protocol_index`
    // to pass to libp2p or that libp2p produces.
    iter::once(peers::ConfigRequestResponse {
        name: "/ipfs/id/1.0.0".into(),
        inbound_config: peers::ConfigRequestResponseIn::Empty,
        max_response_size: 4096,
        inbound_allowed: true,
    })
    .chain(chains.flat_map(|chain| {
        // TODO: limits are arbitrary
        iter::once(peers::ConfigRequestResponse {
            name: format!("/{}/sync/2", chain.protocol_id),
            inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
            max_response_size: 16 * 1024 * 1024,
            inbound_allowed: chain.allow_inbound_block_requests,
        })
        .chain(iter::once(peers::ConfigRequestResponse {
            name: format!("/{}/light/2", chain.protocol_id),
            inbound_config: peers::ConfigRequestResponseIn::Payload {
                max_size: 1024 * 512,
            },
            max_response_size: 10 * 1024 * 1024,
            // TODO: make this configurable
            inbound_allowed: false,
        }))
        .chain(iter::once(peers::ConfigRequestResponse {
            name: format!("/{}/kad", chain.protocol_id),
            inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
            max_response_size: 1024 * 1024,
            // TODO: `false` here means we don't insert ourselves in the DHT, which is the polite thing to do for as long as Kad isn't implemented
            inbound_allowed: false,
        }))
        .chain(iter::once(peers::ConfigRequestResponse {
            name: format!("/{}/sync/warp", chain.protocol_id),
            inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 32 },
            max_response_size: 16 * 1024 * 1024,
            // We don't support inbound warp sync requests (yet).
            inbound_allowed: false,
        }))
        .chain(iter::once(peers::ConfigRequestResponse {
            name: format!("/{}/state/2", chain.protocol_id),
            inbound_config: peers::ConfigRequestResponseIn::Payload { max_size: 1024 },
            // The sender tries to cap the response to 2MiB. However, if one storage item
            // is larger than 2MiB, the response is allowed to be bigger, as otherwise it
            // wouldn't be possible to make progress.
            max_response_size: 16 * 1024 * 1024,
            // We don't support inbound state requests (yet).
            inbound_allowed: false,
        }))
    }))
    .collect()
}

impl<TNow> ChainNetwork<TNow>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Called when the underlying state machine has generated a [`peers::Event::Response`].
    pub(super) fn on_response(
        &mut self,
        request_id: peers::OutRequestId,
        response: Result<Vec<u8>, peers::RequestError>,
    ) -> Event {
        match self.out_requests_types.remove(&request_id).unwrap() {
            (OutRequestTy::Blocks { checked }, chain_index) => {
                let mut response =
                    response
                        .map_err(BlocksRequestError::Request)
                        .and_then(|payload| {
                            protocol::decode_block_response(&payload)
                                .map_err(BlocksRequestError::Decode)
                        });

                if let (Some(config), &mut Ok(ref mut blocks)) = (checked, &mut response) {
                    if let Err(err) = check_blocks_response(
                        self.chains[chain_index].chain_config.block_number_bytes,
                        config,
                        blocks,
                    ) {
                        response = Err(err);
                    }
                }

                Event::RequestResult {
                    request_id,
                    response: RequestResult::Blocks(response),
                }
            }
            (OutRequestTy::GrandpaWarpSync, chain_index) => {
                let block_number_bytes = self.chains[chain_index].chain_config.block_number_bytes;

                let response = response
                    .map_err(GrandpaWarpSyncRequestError::Request)
                    .and_then(|message| {
                        if let Err(err) = protocol::decode_grandpa_warp_sync_response(
                            &message,
                            block_number_bytes,
                        ) {
                            Err(GrandpaWarpSyncRequestError::Decode(err))
                        } else {
                            Ok(EncodedGrandpaWarpSyncResponse {
                                message,
                                block_number_bytes,
                            })
                        }
                    });

                Event::RequestResult {
                    request_id,
                    response: RequestResult::GrandpaWarpSync(response),
                }
            }
            (OutRequestTy::State, _) => {
                let response = response
                    .map_err(StateRequestError::Request)
                    .and_then(|payload| {
                        if let Err(err) = protocol::decode_state_response(&payload) {
                            Err(StateRequestError::Decode(err))
                        } else {
                            Ok(EncodedStateResponse(payload))
                        }
                    });

                Event::RequestResult {
                    request_id,
                    response: RequestResult::State(response),
                }
            }
            (OutRequestTy::StorageProof, _) => {
                let response = response
                    .map_err(StorageProofRequestError::Request)
                    .and_then(|payload| {
                        match protocol::decode_storage_or_call_proof_response(
                            protocol::StorageOrCallProof::StorageProof,
                            &payload,
                        ) {
                            Err(err) => Err(StorageProofRequestError::Decode(err)),
                            Ok(None) => Err(StorageProofRequestError::RemoteCouldntAnswer),
                            Ok(Some(_)) => Ok(EncodedMerkleProof(
                                payload,
                                protocol::StorageOrCallProof::StorageProof,
                            )),
                        }
                    });

                Event::RequestResult {
                    request_id,
                    response: RequestResult::StorageProof(response),
                }
            }
            (OutRequestTy::CallProof, _) => {
                let response =
                    response
                        .map_err(CallProofRequestError::Request)
                        .and_then(
                            |payload| match protocol::decode_storage_or_call_proof_response(
                                protocol::StorageOrCallProof::CallProof,
                                &payload,
                            ) {
                                Err(err) => Err(CallProofRequestError::Decode(err)),
                                Ok(None) => Err(CallProofRequestError::RemoteCouldntAnswer),
                                Ok(Some(_)) => Ok(EncodedMerkleProof(
                                    payload,
                                    protocol::StorageOrCallProof::CallProof,
                                )),
                            },
                        );

                Event::RequestResult {
                    request_id,
                    response: RequestResult::CallProof(response),
                }
            }
            (OutRequestTy::KademliaFindNode, _) => {
                let response = response
                    .map_err(KademliaFindNodeError::RequestFailed)
                    .and_then(|payload| {
                        protocol::decode_find_node_response(&payload)
                            .map_err(KademliaFindNodeError::DecodeError)
                    });

                Event::RequestResult {
                    request_id,
                    response: RequestResult::KademliaFindNode(response),
                }
            }
            (OutRequestTy::KademliaDiscoveryFindNode(operation_id), _) => {
                let result = response
                    .map_err(KademliaFindNodeError::RequestFailed)
                    .and_then(|payload| {
                        protocol::decode_find_node_response(&payload)
                            .map_err(KademliaFindNodeError::DecodeError)
                    })
                    .map_err(DiscoveryError::FindNode);

                Event::KademliaDiscoveryResult {
                    operation_id,
                    result,
                }
            }
        }
    }

    /// Called when the underlying state machine has generated a [`peers::Event::RequestIn`].
    pub(super) fn on_request_in(
        &mut self,
        request_id: InRequestId,
        peer_id: PeerId,
        connection_id: ConnectionId,
        protocol_index: usize,
        request_payload: Vec<u8>,
    ) -> Event {
        if protocol_index == 0 {
            if request_payload.is_empty() {
                let observed_addr = self.inner[connection_id].clone();
                let _prev_value = self
                    .in_requests_types
                    .insert(request_id, InRequestTy::Identify { observed_addr });
                debug_assert!(_prev_value.is_none());

                Event::IdentifyRequestIn {
                    peer_id,
                    request_id,
                }
            } else {
                let _ = self.inner.respond_in_request(request_id, Err(()));
                Event::ProtocolError {
                    peer_id,
                    error: ProtocolError::BadIdentifyRequest,
                }
            }
        } else if ((protocol_index - 1) % requests_responses::REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN)
            != 0
        {
            // Protocols that receive requests are whitelisted, meaning that no other protocol
            // indices can reach here.
            unreachable!()
        } else {
            let chain_index =
                (protocol_index - 1) / requests_responses::REQUEST_RESPONSE_PROTOCOLS_PER_CHAIN;

            match protocol::decode_block_request(
                self.chains[chain_index].chain_config.block_number_bytes,
                &request_payload,
            ) {
                Ok(config) => {
                    let _prev_value = self
                        .in_requests_types
                        .insert(request_id, InRequestTy::Blocks);
                    debug_assert!(_prev_value.is_none());

                    Event::BlocksRequestIn {
                        peer_id,
                        chain_index,
                        config,
                        request_id,
                    }
                }
                Err(error) => {
                    let _ = self.inner.respond_in_request(request_id, Err(()));
                    Event::ProtocolError {
                        peer_id,
                        error: ProtocolError::BadBlocksRequest(error),
                    }
                }
            }
        }
    }

    /// Called when the underlying state machine has generated a [`peers::Event::RequestInCancel`].
    pub(super) fn on_request_in_cancel(&mut self, id: InRequestId) -> Event {
        self.in_requests_types.remove(&id).unwrap();
        Event::RequestInCancel { request_id: id }
    }

    /// Sends a blocks request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_blocks_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> OutRequestId {
        self.start_blocks_request_inner(now, target, chain_index, config, timeout, true)
    }

    /// Sends a blocks request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_blocks_request_unchecked(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> OutRequestId {
        self.start_blocks_request_inner(now, target, chain_index, config, timeout, false)
    }

    fn start_blocks_request_inner(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
        checked: bool,
    ) -> OutRequestId {
        let request_data = protocol::build_block_request(
            self.chains[chain_index].chain_config.block_number_bytes,
            &config,
        )
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 0),
            request_data,
            now + timeout,
        );

        let _prev_value = self.out_requests_types.insert(
            id,
            (
                OutRequestTy::Blocks {
                    checked: if checked { Some(config) } else { None },
                },
                chain_index,
            ),
        );
        debug_assert!(_prev_value.is_none());

        id
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_grandpa_warp_sync_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> OutRequestId {
        let request_data = begin_hash.to_vec();

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 3),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::GrandpaWarpSync, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a state request to a peer.
    ///
    /// A state request makes it possible to download the storage of the chain at a given block.
    /// The response is not unverified by this function. In other words, the peer is free to send
    /// back erroneous data. It is the responsibility of the API user to verify the storage by
    /// calculating the state trie root hash and comparing it with the value stored in the
    /// block's header.
    ///
    /// Because response have a size limit, it is unlikely that a single request will return the
    /// entire storage of the chain at once. Instead, call this function multiple times, each call
    /// passing a `start_key` that follows the last key of the previous response.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_state_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        block_hash: &[u8; 32],
        start_key: protocol::StateRequestStart,
        timeout: Duration,
    ) -> OutRequestId {
        let request_data = protocol::build_state_request(protocol::StateRequest {
            block_hash,
            start_key,
        })
        .fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 4),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::State, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a storage request to the given peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    // TODO: more docs
    pub fn start_storage_proof_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> OutRequestId {
        let request_data =
            protocol::build_storage_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 1),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::StorageProof, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Sends a call proof request to the given peer.
    ///
    /// This request is similar to [`ChainNetwork::start_storage_proof_request`]. Instead of
    /// requesting specific keys, we request the list of all the keys that are accessed for a
    /// specific runtime call.
    ///
    /// There exists no guarantee that the proof is complete (i.e. that it contains all the
    /// necessary entries), as it is impossible to know this from just the proof itself. As such,
    /// this method is just an optimization. When performing the actual call, regular storage proof
    /// requests should be performed if the key is not present in the call proof response.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_call_proof_request(
        &mut self,
        now: TNow,
        target: &PeerId,
        chain_index: usize,
        config: protocol::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> OutRequestId {
        let request_data =
            protocol::build_call_proof_request(config).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 1),
            request_data,
            now + timeout,
        );

        let _prev_value = self
            .out_requests_types
            .insert(id, (OutRequestTy::CallProof, chain_index));
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Inserts the given list of nodes into the list of known nodes held within the state machine.
    pub fn discover(
        &mut self,
        now: &TNow,
        chain_index: usize,
        peer_id: PeerId,
        discovered_addrs: impl IntoIterator<Item = multiaddr::Multiaddr>,
    ) {
        let kbuckets = &mut self.chains[chain_index].kbuckets;

        let mut discovered_addrs = discovered_addrs.into_iter().peekable();

        // Check whether there is any address in the iterator at all before inserting the
        // node in the buckets.
        if discovered_addrs.peek().is_none() {
            return;
        }

        let kbuckets_peer = match kbuckets.entry(&peer_id) {
            kademlia::kbuckets::Entry::LocalKey => return, // TODO: return some diagnostic?
            kademlia::kbuckets::Entry::Vacant(entry) => {
                match entry.insert((), now, kademlia::kbuckets::PeerState::Disconnected) {
                    Err(kademlia::kbuckets::InsertError::Full) => return, // TODO: return some diagnostic?
                    Ok((_, removed_entry)) => {
                        // `removed_entry` is the peer that was removed the k-buckets as the
                        // result of the new insertion. Purge it from `self.kbuckets_peers`
                        // if necessary.
                        if let Some((removed_peer_id, _)) = removed_entry {
                            match self.kbuckets_peers.entry(removed_peer_id) {
                                hashbrown::hash_map::Entry::Occupied(e)
                                    if e.get().num_references.get() == 1 =>
                                {
                                    e.remove();
                                }
                                hashbrown::hash_map::Entry::Occupied(e) => {
                                    let num_refs = &mut e.into_mut().num_references;
                                    *num_refs = NonZeroUsize::new(num_refs.get() - 1).unwrap();
                                }
                                hashbrown::hash_map::Entry::Vacant(_) => unreachable!(),
                            }
                        }

                        match self.kbuckets_peers.entry(peer_id) {
                            hashbrown::hash_map::Entry::Occupied(e) => {
                                let e = e.into_mut();
                                e.num_references = e.num_references.checked_add(1).unwrap();
                                e
                            }
                            hashbrown::hash_map::Entry::Vacant(e) => {
                                // The peer was not in the k-buckets, but it is possible that
                                // we already have existing connections to it.
                                let mut addresses = addresses::Addresses::with_capacity(
                                    self.max_addresses_per_peer.get(),
                                );

                                for connection_id in
                                    self.inner.established_peer_connections(&e.key())
                                {
                                    let state = self.inner.connection_state(connection_id);
                                    debug_assert!(state.established);
                                    // Because we mark addresses as disconnected when the
                                    // shutdown process starts, we ignore shutting down
                                    // connections.
                                    if state.shutting_down {
                                        continue;
                                    }
                                    if state.outbound {
                                        addresses
                                            .insert_discovered(self.inner[connection_id].clone());
                                        addresses.set_connected(&self.inner[connection_id]);
                                    }
                                }

                                for connection_id in
                                    self.inner.handshaking_peer_connections(&e.key())
                                {
                                    let state = self.inner.connection_state(connection_id);
                                    debug_assert!(!state.established);
                                    debug_assert!(state.outbound);
                                    // Because we mark addresses as disconnected when the
                                    // shutdown process starts, we ignore shutting down
                                    // connections.
                                    if state.shutting_down {
                                        continue;
                                    }
                                    addresses.insert_discovered(self.inner[connection_id].clone());
                                    addresses.set_pending(&self.inner[connection_id]);
                                }

                                // TODO: O(n)
                                for (_, (p, addr, _)) in &self.pending_ids {
                                    if p == e.key() {
                                        addresses.insert_discovered(addr.clone());
                                        addresses.set_pending(addr);
                                    }
                                }

                                e.insert(KBucketsPeer {
                                    num_references: NonZeroUsize::new(1).unwrap(),
                                    addresses,
                                })
                            }
                        }
                    }
                }
            }
            kademlia::kbuckets::Entry::Occupied(_) => {
                self.kbuckets_peers.get_mut(&peer_id).unwrap()
            }
        };

        for to_insert in discovered_addrs {
            if kbuckets_peer.addresses.len() >= self.max_addresses_per_peer.get() {
                continue;
            }

            kbuckets_peer.addresses.insert_discovered(to_insert);
        }

        // List of addresses must never be empty.
        debug_assert!(!kbuckets_peer.addresses.is_empty());
    }

    /// Performs a round of Kademlia discovery.
    ///
    /// This future yields once a list of nodes on the network has been discovered, or a problem
    /// happened.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_kademlia_discovery_round(
        &'_ mut self,
        now: TNow,
        chain_index: usize,
    ) -> KademliaOperationId {
        let random_peer_id = {
            let pub_key = self.randomness.sample(rand::distributions::Standard);
            PeerId::from_public_key(&peer_id::PublicKey::Ed25519(pub_key))
        };

        let queried_peer = {
            let peer_id = self.chains[chain_index]
                .kbuckets
                .closest_entries(&random_peer_id)
                // TODO: instead of filtering by connectd only, connect to nodes if not connected
                // TODO: additionally, this only takes outgoing connections into account
                .find(|(peer_id, _)| {
                    self.kbuckets_peers
                        .get(*peer_id)
                        .unwrap()
                        .addresses
                        .iter_connected()
                        .next()
                        .is_some()
                })
                .map(|(peer_id, _)| peer_id.clone());
            peer_id
        };

        let kademlia_operation_id = self.next_kademlia_operation_id;
        self.next_kademlia_operation_id.0 += 1;

        if let Some(queried_peer) = queried_peer {
            debug_assert!(self
                .inner
                .established_peer_connections(&queried_peer)
                .any(|cid| !self.inner.connection_state(cid).shutting_down));

            self.start_kademlia_find_node_inner(
                &queried_peer,
                now,
                chain_index,
                random_peer_id.as_bytes(),
                Some(kademlia_operation_id),
            );
        } else {
            self.pending_kademlia_errors
                .push_back((kademlia_operation_id, DiscoveryError::NoPeer))
        }

        kademlia_operation_id
    }

    /// Sends a Kademlia "find node" request to a single peer, and waits for it to answer.
    ///
    /// Returns an error if there is no active connection with that peer.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn start_kademlia_find_node(
        &mut self,
        target: &PeerId,
        now: TNow,
        chain_index: usize,
        close_to_key: &[u8],
    ) -> OutRequestId {
        self.start_kademlia_find_node_inner(target, now, chain_index, close_to_key, None)
    }

    fn start_kademlia_find_node_inner(
        &mut self,
        target: &PeerId,
        now: TNow,
        chain_index: usize,
        close_to_key: &[u8],
        part_of_operation: Option<KademliaOperationId>,
    ) -> OutRequestId {
        let request_data = protocol::build_find_node_request(close_to_key);
        // The timeout needs to be long enough to potentially download the maximum
        // response size of 1 MiB. Assuming a 128 kiB/sec connection, that's 8 seconds.
        let timeout = now + Duration::from_secs(8);

        let id = self.inner.start_request(
            target,
            self.protocol_index(chain_index, 2),
            request_data,
            timeout,
        );

        let _prev_value = self.out_requests_types.insert(
            id,
            (
                if let Some(operation_id) = part_of_operation {
                    OutRequestTy::KademliaDiscoveryFindNode(operation_id)
                } else {
                    OutRequestTy::KademliaFindNode
                },
                chain_index,
            ),
        );
        debug_assert!(_prev_value.is_none());

        id
    }

    /// Returns `true` if if it possible to send requests (i.e. through
    /// [`ChainNetwork::start_grandpa_warp_sync_request`],
    /// [`ChainNetwork::start_blocks_request`], etc.) to the given peer.
    ///
    /// If `false` is returned, starting a request will panic.
    ///
    /// In other words, returns `true` if there exists an established connection non-shutting-down
    /// connection with the given peer.
    pub fn can_start_requests(&self, peer_id: &PeerId) -> bool {
        self.inner.can_start_requests(peer_id)
    }

    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn respond_identify(&mut self, request_id: InRequestId, agent_version: &str) {
        let observed_addr = match self.in_requests_types.remove(&request_id) {
            Some(InRequestTy::Identify { observed_addr }) => observed_addr,
            _ => panic!(),
        };

        let response = {
            protocol::build_identify_response(protocol::IdentifyResponse {
                protocol_version: "/substrate/1.0", // TODO: same value as in Substrate
                agent_version,
                ed25519_public_key: *self.inner.noise_key().libp2p_public_ed25519_key(),
                listen_addrs: iter::empty(), // TODO:
                observed_addr,
                protocols: self
                    .inner
                    .request_response_protocols()
                    .filter(|p| p.inbound_allowed)
                    .map(|p| &p.name[..])
                    .chain(
                        self.inner
                            .notification_protocols()
                            .map(|p| &p.protocol_name[..]),
                    ),
            })
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            })
        };

        let _ = self.inner.respond_in_request(request_id, Ok(response));
    }

    /// Queue the response to send back.
    ///
    /// Pass `None` in order to deny the request. Do this if blocks aren't available locally.
    ///
    /// Has no effect if the connection that sends the request no longer exists.
    ///
    /// This function might generate a message destined a connection. Use
    /// [`ChainNetwork::pull_message_to_connection`] to process messages after it has returned.
    pub fn respond_blocks(
        &mut self,
        request_id: InRequestId,
        response: Option<Vec<protocol::BlockData>>,
    ) {
        match self.in_requests_types.remove(&request_id) {
            Some(InRequestTy::Blocks) => {}
            _ => panic!(),
        };

        let response = if let Some(response) = response {
            Ok(
                protocol::build_block_response(response).fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }),
            )
        } else {
            Err(())
        };

        let _ = self.inner.respond_in_request(request_id, response);
    }
}

/// Response to an outgoing request.
///
/// See [`Event::RequestResult`̀].
#[derive(Debug)]
pub enum RequestResult {
    Blocks(Result<Vec<protocol::BlockData>, BlocksRequestError>),
    GrandpaWarpSync(Result<EncodedGrandpaWarpSyncResponse, GrandpaWarpSyncRequestError>),
    State(Result<EncodedStateResponse, StateRequestError>),
    StorageProof(Result<EncodedMerkleProof, StorageProofRequestError>),
    CallProof(Result<EncodedMerkleProof, CallProofRequestError>),
    KademliaFindNode(
        Result<Vec<(peer_id::PeerId, Vec<multiaddr::Multiaddr>)>, KademliaFindNodeError>,
    ),
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

/// Undecoded but valid Merkle proof.
#[derive(Clone)]
pub struct EncodedMerkleProof(Vec<u8>, protocol::StorageOrCallProof);

impl EncodedMerkleProof {
    /// Returns the SCALE-encoded Merkle proof.
    pub fn decode(&self) -> &[u8] {
        protocol::decode_storage_or_call_proof_response(self.1, &self.0)
            .unwrap()
            .unwrap()
    }
}

impl fmt::Debug for EncodedMerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid GrandPa warp sync response.
#[derive(Clone)]
pub struct EncodedGrandpaWarpSyncResponse {
    message: Vec<u8>,
    block_number_bytes: usize,
}

impl EncodedGrandpaWarpSyncResponse {
    /// Returns the encoded bytes of the warp sync message.
    pub fn as_encoded(&self) -> &[u8] {
        &self.message
    }

    /// Returns the decoded version of the warp sync message.
    pub fn decode(&self) -> protocol::GrandpaWarpSyncResponse {
        match protocol::decode_grandpa_warp_sync_response(&self.message, self.block_number_bytes) {
            Ok(msg) => msg,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for EncodedGrandpaWarpSyncResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Undecoded but valid state response.
#[derive(Clone)]
pub struct EncodedStateResponse(Vec<u8>);

impl EncodedStateResponse {
    /// Returns the decoded version of the state response.
    pub fn decode(&self) -> Vec<&[u8]> {
        match protocol::decode_state_response(&self.0) {
            Ok(r) => r,
            Err(_) => unreachable!(),
        }
    }
}

impl fmt::Debug for EncodedStateResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.decode(), f)
    }
}

/// Error during [`ChainNetwork::start_kademlia_discovery_round`].
#[derive(Debug, derive_more::Display)]
pub enum DiscoveryError {
    /// Not currently connected to any other node.
    NoPeer,
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    FindNode(KademliaFindNodeError),
}

/// Error during [`ChainNetwork::start_kademlia_find_node`].
#[derive(Debug, derive_more::Display)]
pub enum KademliaFindNodeError {
    /// Error during the request.
    #[display(fmt = "{}", _0)]
    RequestFailed(peers::RequestError),
    /// Failed to decode the response.
    #[display(fmt = "Response decoding error: {}", _0)]
    DecodeError(protocol::DecodeFindNodeResponseError),
}

/// Error returned by [`ChainNetwork::start_blocks_request`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestError {
    /// Error while waiting for the response from the peer.
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    /// Error while decoding the response returned by the peer.
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeBlockResponseError),
    /// Block request doesn't request headers, and as such its validity cannot be verified.
    NotVerifiable,
    /// Response returned by the remote doesn't contain any entry.
    EmptyResponse,
    /// Start of the response doesn't correspond to the requested start.
    InvalidStart,
    /// Error at a specific index in the response.
    #[display(fmt = "Error in response at offset {}: {}", index, error)]
    Entry {
        /// Index in the response where the problem happened.
        index: usize,
        /// Problem in question.
        error: BlocksRequestResponseEntryError,
    },
}

/// See [`BlocksRequestError`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestResponseEntryError {
    /// One of the requested fields is missing from the block.
    MissingField,
    /// The header has an extrinsics root that doesn't match the body. Can only happen if both the
    /// header and body were requested.
    #[display(fmt = "The header has an extrinsics root that doesn't match the body")]
    InvalidExtrinsicsRoot {
        /// Extrinsics root that was calculated from the body.
        calculated: [u8; 32],
        /// Extrinsics root found in the header.
        in_header: [u8; 32],
    },
    /// The header has an invalid format.
    InvalidHeader,
    /// The hash of the header doesn't match the hash provided by the remote.
    InvalidHash,
}

/// Error returned by [`ChainNetwork::start_storage_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StorageProofRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStorageCallProofResponseError),
    /// The remote is incapable of answering this specific request.
    RemoteCouldntAnswer,
}

/// Error returned by [`ChainNetwork::start_call_proof_request`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum CallProofRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStorageCallProofResponseError),
    /// The remote is incapable of answering this specific request.
    RemoteCouldntAnswer,
}

impl CallProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            CallProofRequestError::Request(_) => true,
            CallProofRequestError::Decode(_) => false,
            CallProofRequestError::RemoteCouldntAnswer => true,
        }
    }
}

/// Error returned by [`ChainNetwork::start_grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display)]
pub enum GrandpaWarpSyncRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeGrandpaWarpSyncResponseError),
}

/// Error returned by [`ChainNetwork::start_state_request`].
#[derive(Debug, derive_more::Display)]
pub enum StateRequestError {
    #[display(fmt = "{}", _0)]
    Request(peers::RequestError),
    #[display(fmt = "Response decoding error: {}", _0)]
    Decode(protocol::DecodeStateResponseError),
}

fn check_blocks_response(
    block_number_bytes: usize,
    config: protocol::BlocksRequestConfig,
    result: &mut [protocol::BlockData],
) -> Result<(), BlocksRequestError> {
    if !config.fields.header {
        return Err(BlocksRequestError::NotVerifiable);
    }

    if result.is_empty() {
        return Err(BlocksRequestError::EmptyResponse);
    }

    // Verify validity of all the blocks.
    for (block_index, block) in result.iter_mut().enumerate() {
        if block.header.is_none() {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::MissingField,
            });
        }

        if block
            .header
            .as_ref()
            .map_or(false, |h| header::decode(h, block_number_bytes).is_err())
        {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::InvalidHeader,
            });
        }

        match (block.body.is_some(), config.fields.body) {
            (false, true) => {
                return Err(BlocksRequestError::Entry {
                    index: block_index,
                    error: BlocksRequestResponseEntryError::MissingField,
                });
            }
            (true, false) => {
                block.body = None;
            }
            _ => {}
        }

        // Note: the presence of a justification isn't checked and can't be checked, as not
        // all blocks have a justification in the first place.

        if block.header.as_ref().map_or(false, |h| {
            header::hash_from_scale_encoded_header(&h) != block.hash
        }) {
            return Err(BlocksRequestError::Entry {
                index: block_index,
                error: BlocksRequestResponseEntryError::InvalidHash,
            });
        }

        if let (Some(header), Some(body)) = (&block.header, &block.body) {
            let decoded_header = header::decode(header, block_number_bytes).unwrap();
            let expected = header::extrinsics_root(&body[..]);
            if expected != *decoded_header.extrinsics_root {
                return Err(BlocksRequestError::Entry {
                    index: block_index,
                    error: BlocksRequestResponseEntryError::InvalidExtrinsicsRoot {
                        calculated: expected,
                        in_header: *decoded_header.extrinsics_root,
                    },
                });
            }
        }
    }

    match config.start {
        protocol::BlocksRequestConfigStart::Hash(hash) if result[0].hash != hash => {
            return Err(BlocksRequestError::InvalidStart);
        }
        protocol::BlocksRequestConfigStart::Number(n)
            if header::decode(result[0].header.as_ref().unwrap(), block_number_bytes)
                .unwrap()
                .number
                != n =>
        {
            return Err(BlocksRequestError::InvalidStart)
        }
        _ => {}
    }

    Ok(())
}
