use crate::{
    chain::chain_information::{
        babe_fetch_epoch, BabeEpochInformation, ChainInformation, ChainInformationConsensus,
        ChainInformationFinality,
    },
    executor::{
        host::{HostVmPrototype, NewErr},
        vm::ExecHint,
    },
    finality::{grandpa::warp_sync, justification::verify},
    header::Header,
    libp2p::PeerId,
    network::protocol::GrandpaWarpSyncResponseFragment,
};

/// Problem encountered during a call to [`grandpa_warp_sync`].
#[derive(Debug, derive_more::Display)]
pub enum Error {
    #[display(fmt = "Missing code or heap pages")]
    MissingCodeOrHeapPages,
    #[display(fmt = "Failed to parse heap pages: {}", _0)]
    FailedToParseHeapPages(std::array::TryFromSliceError),
    #[display(fmt = "{}", _0)]
    Verifier(verify::Error),
    #[display(fmt = "{}", _0)]
    BabeFetchEpoch(babe_fetch_epoch::Error),
    #[display(fmt = "{}", _0)]
    NewRuntime(NewErr),
}

/// The configuration for [`grandpa_warp_sync`].
pub struct Config {
    /// The chain information of the genesis block.
    pub genesis_chain_information: ChainInformation,
}

/// Starts syncing via GrandPa warp sync.
pub fn grandpa_warp_sync(config: Config) -> GrandpaWarpSync {
    GrandpaWarpSync::WaitingForPeers(WaitingForPeers {
        genesis_chain_information: config.genesis_chain_information,
        peers: Vec::new(),
    })
}

/// The GrandPa warp sync state machine.
pub enum GrandpaWarpSync {
    /// Warp syncing is over.
    Finished(Result<(ChainInformation, HostVmPrototype), Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
    /// Verifying the warp sync response is required to continue.
    Verifier(Verifier),
    /// Performing a network request is required to continue.
    WarpSyncRequest(WarpSyncRequest),
    /// Fetching the parameters for the virtual machine is required to continue.
    VirtualMachineParamsGet(VirtualMachineParamsGet),
    /// Adding more peers to perform GrandPa warp sync network requests to is required to continue.
    WaitingForPeers(WaitingForPeers),
}

impl GrandpaWarpSync {
    fn from_babe_fetch_epoch_query(
        query: babe_fetch_epoch::Query,
        fetched_current_epoch: Option<BabeEpochInformation>,
        state: PostVerificationState,
    ) -> Self {
        match (query, fetched_current_epoch) {
            (babe_fetch_epoch::Query::Finished(Ok((next_epoch, runtime))), Some(current_epoch)) => {
                let slots_per_epoch = match state.genesis_chain_information.consensus {
                    ChainInformationConsensus::Babe {
                        slots_per_epoch, ..
                    } => slots_per_epoch,
                    _ => unreachable!(),
                };

                Self::Finished(Ok((
                    ChainInformation {
                        finalized_block_header: state.header,
                        finality: state.chain_information_finality,
                        consensus: ChainInformationConsensus::Babe {
                            finalized_block_epoch_information: Some(current_epoch),
                            finalized_next_epoch_transition: next_epoch,
                            slots_per_epoch,
                        },
                    },
                    runtime,
                )))
            }
            (babe_fetch_epoch::Query::Finished(Ok((current_epoch, runtime))), None) => {
                let babe_next_epoch_query =
                    babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                        runtime,
                        epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::NextEpoch,
                    });
                Self::from_babe_fetch_epoch_query(babe_next_epoch_query, Some(current_epoch), state)
            }
            (babe_fetch_epoch::Query::Finished(Err(error)), _) => {
                Self::Finished(Err(Error::BabeFetchEpoch(error)))
            }
            (babe_fetch_epoch::Query::StorageGet(storage_get), fetched_current_epoch) => {
                Self::StorageGet(StorageGet {
                    inner: storage_get,
                    fetched_current_epoch,
                    state,
                })
            }
            (babe_fetch_epoch::Query::NextKey(next_key), fetched_current_epoch) => {
                Self::NextKey(NextKey {
                    inner: next_key,
                    fetched_current_epoch,
                    state,
                })
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: babe_fetch_epoch::StorageGet,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'a>(&'a self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.inner.key()
    }

    /// Returns the peer that we received the warp sync data from.
    pub fn warp_sync_peer(&self) -> PeerId {
        self.state.warp_sync_peer.clone()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.inner.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> GrandpaWarpSync {
        GrandpaWarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_value(value),
            self.fetched_current_epoch,
            self.state,
        )
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey {
    inner: babe_fetch_epoch::NextKey,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState,
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        self.inner.key()
    }

    /// Returns the peer that we received the warp sync data from.
    pub fn warp_sync_peer(&self) -> PeerId {
        self.state.warp_sync_peer.clone()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> GrandpaWarpSync {
        GrandpaWarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_key(key),
            self.fetched_current_epoch,
            self.state,
        )
    }
}

/// Verifying the warp sync response is required to continue.
pub struct Verifier {
    verifier: warp_sync::Verifier,
    genesis_chain_information: ChainInformation,
    warp_sync_peer: PeerId,
}

impl Verifier {
    pub fn next(self) -> GrandpaWarpSync {
        match self.verifier.next() {
            Ok(warp_sync::Next::NotFinished(next_verifier)) => GrandpaWarpSync::Verifier(Self {
                verifier: next_verifier,
                genesis_chain_information: self.genesis_chain_information,
                warp_sync_peer: self.warp_sync_peer,
            }),
            Ok(warp_sync::Next::Success {
                header,
                chain_information_finality,
            }) => GrandpaWarpSync::VirtualMachineParamsGet(VirtualMachineParamsGet {
                state: PostVerificationState {
                    header,
                    chain_information_finality,
                    genesis_chain_information: self.genesis_chain_information,
                    warp_sync_peer: self.warp_sync_peer,
                },
            }),
            Err(error) => GrandpaWarpSync::Finished(Err(Error::Verifier(error))),
        }
    }
}

struct PostVerificationState {
    header: Header,
    chain_information_finality: ChainInformationFinality,
    genesis_chain_information: ChainInformation,
    warp_sync_peer: PeerId,
}

/// Performing a GrandPa warp sync network request is required to continue.
pub struct WarpSyncRequest {
    peer_index: usize,
    peers: Vec<PeerId>,
    genesis_chain_information: ChainInformation,
}

impl WarpSyncRequest {
    /// The peer to make a GrandPa warp sync network request to.
    pub fn current_peer(&self) -> PeerId {
        self.peers[self.peer_index].clone()
    }

    /// Add a peer to the list of peers.
    pub fn add_peer(&mut self, peer: PeerId) {
        self.peers.push(peer);
    }

    /// Remove a peer from the list of peers.
    pub fn remove(mut self, to_remove: PeerId) -> GrandpaWarpSync {
        if to_remove == self.current_peer() {
            let next_index = self.peer_index + 1;

            if next_index == self.peers.len() {
                GrandpaWarpSync::WaitingForPeers(WaitingForPeers {
                    peers: Vec::new(),
                    genesis_chain_information: self.genesis_chain_information,
                })
            } else {
                GrandpaWarpSync::WarpSyncRequest(Self {
                    peer_index: next_index,
                    peers: self.peers,
                    genesis_chain_information: self.genesis_chain_information,
                })
            }
        } else {
            let index = self.peers.iter().position(|peer| peer == &to_remove);

            if let Some(index) = index {
                // There's no point in removing a peer if it's behind the current index.
                if index > self.peer_index {
                    self.peers.remove(index);
                }
            }

            GrandpaWarpSync::WarpSyncRequest(self)
        }
    }

    /// Submit a GrandPa warp sync network response if the request succeeded or
    /// `None` if it did not.
    pub async fn handle_response(
        self,
        response: Option<Vec<GrandpaWarpSyncResponseFragment>>,
    ) -> GrandpaWarpSync {
        let warp_sync_peer = self.current_peer();

        let next_index = self.peer_index + 1;

        match response {
            Some(response_fragments) => GrandpaWarpSync::Verifier(Verifier {
                verifier: warp_sync::Verifier::new(
                    &self.genesis_chain_information,
                    response_fragments,
                ),
                genesis_chain_information: self.genesis_chain_information,
                warp_sync_peer,
            }),
            None if next_index < self.peers.len() => GrandpaWarpSync::WarpSyncRequest(Self {
                peer_index: next_index,
                peers: self.peers,
                genesis_chain_information: self.genesis_chain_information,
            }),
            None => GrandpaWarpSync::WaitingForPeers(WaitingForPeers {
                peers: Vec::new(),
                genesis_chain_information: self.genesis_chain_information,
            }),
        }
    }
}

/// Fetching the parameters for the virtual machine is required to continue.
pub struct VirtualMachineParamsGet {
    state: PostVerificationState,
}

impl VirtualMachineParamsGet {
    /// Set the code and heappages from storage using the keys `:code` and `:heappages`
    /// respectively. Also allows setting an execution hint for the virtual machine.
    pub fn inject_virtual_machine_params(
        self,
        code: Option<impl AsRef<[u8]>>,
        heap_pages: Option<impl AsRef<[u8]>>,
        exec_hint: ExecHint,
    ) -> GrandpaWarpSync {
        let (code, heap_pages) = match (code, heap_pages) {
            (Some(code), Some(heap_pages)) => {
                use std::convert::TryInto;

                let heap_pages = match heap_pages.as_ref().try_into() {
                    Ok(heap_pages) => heap_pages,
                    Err(error) => {
                        return GrandpaWarpSync::Finished(Err(Error::FailedToParseHeapPages(error)))
                    }
                };

                (code, u64::from_le_bytes(heap_pages))
            }
            _ => return GrandpaWarpSync::Finished(Err(Error::MissingCodeOrHeapPages)),
        };

        match HostVmPrototype::new(code, heap_pages, exec_hint) {
            Ok(runtime) => {
                let babe_current_epoch_query =
                    babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                        runtime,
                        epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::CurrentEpoch,
                    });

                GrandpaWarpSync::from_babe_fetch_epoch_query(
                    babe_current_epoch_query,
                    None,
                    self.state,
                )
            }
            Err(error) => GrandpaWarpSync::Finished(Err(Error::NewRuntime(error))),
        }
    }
}

/// Adding more peers to perform GrandPa warp sync network requests to is required to continue.
pub struct WaitingForPeers {
    peers: Vec<PeerId>,
    genesis_chain_information: ChainInformation,
}

impl WaitingForPeers {
    /// Add a peer to the list of peers.
    pub fn add_peer(mut self, peer: PeerId) -> GrandpaWarpSync {
        self.peers.push(peer);
        GrandpaWarpSync::WaitingForPeers(self)
    }

    /// Proceed to issuing GrandPa warp sync requests.
    pub fn ready(self) -> GrandpaWarpSync {
        if self.peers.is_empty() {
            return GrandpaWarpSync::WaitingForPeers(self);
        }

        GrandpaWarpSync::WarpSyncRequest(WarpSyncRequest {
            peer_index: 0,
            peers: self.peers,
            genesis_chain_information: self.genesis_chain_information,
        })
    }
}
