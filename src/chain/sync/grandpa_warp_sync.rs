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
    #[display(fmt = "All requests failed.")]
    AllRequestsFailed,
    #[display(fmt = "{}", _0)]
    Verifier(verify::Error),
    #[display(fmt = "{}", _0)]
    BabeFetchEpoch(babe_fetch_epoch::Error),
    #[display(fmt = "{}", _0)]
    NewRuntime(NewErr),
}

/// The configuration for [`grandpa_warp_sync`].
pub struct Config<'a> {
    /// A list of connected peers.
    pub connected_peers: Vec<PeerId>,
    /// The chain information of the genesis block.
    pub genesis_chain_information: &'a ChainInformation,
}

/// Starts syncing via grandpa warp sync.
pub fn grandpa_warp_sync(config: Config) -> GrandpaWarpSync {
    GrandpaWarpSync::WarpSyncRequest(WarpSyncRequest {
        peer_index: 0,
        connected_peers: config.connected_peers,
        genesis_chain_information: config.genesis_chain_information,
    })
}

/// The grandpa warp sync state machine.
pub enum GrandpaWarpSync<'a> {
    /// Warp syncing is over.
    Finished(Result<(ChainInformation, HostVmPrototype), Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet<'a>),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey<'a>),
    /// Verifying the warp sync response is required to continue.
    Verifier(Verifier<'a>),
    /// Performing a network request is required to continue.
    WarpSyncRequest(WarpSyncRequest<'a>),
    /// Fetching the parameters for the virtual machine is required to continue.
    VirtualMachineParamsGet(VirtualMachineParamsGet<'a>),
}

impl<'a> GrandpaWarpSync<'a> {
    fn from_babe_fetch_epoch_query(
        query: babe_fetch_epoch::Query,
        fetched_current_epoch: Option<BabeEpochInformation>,
        state: PostVerificationState<'a>,
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
pub struct StorageGet<'a> {
    inner: babe_fetch_epoch::StorageGet,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState<'a>,
}

impl<'a> StorageGet<'a> {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'a self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.inner.key()
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
    ) -> GrandpaWarpSync<'a> {
        GrandpaWarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_value(value),
            self.fetched_current_epoch,
            self.state,
        )
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey<'a> {
    inner: babe_fetch_epoch::NextKey,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState<'a>,
}

impl<'a> NextKey<'a> {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        self.inner.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> GrandpaWarpSync<'a> {
        GrandpaWarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_key(key),
            self.fetched_current_epoch,
            self.state,
        )
    }
}

/// Verifying the warp sync response is required to continue.
pub struct Verifier<'a> {
    verifier: warp_sync::Verifier,
    genesis_chain_information: &'a ChainInformation,
}

impl<'a> Verifier<'a> {
    pub fn next(self) -> GrandpaWarpSync<'a> {
        match self.verifier.next() {
            Ok(warp_sync::Next::NotFinished(next_verifier)) => GrandpaWarpSync::Verifier(Self {
                verifier: next_verifier,
                genesis_chain_information: self.genesis_chain_information,
            }),
            Ok(warp_sync::Next::Success {
                header,
                chain_information_finality,
            }) => GrandpaWarpSync::VirtualMachineParamsGet(VirtualMachineParamsGet {
                state: PostVerificationState {
                    header,
                    chain_information_finality,
                    genesis_chain_information: self.genesis_chain_information,
                },
            }),
            Err(error) => GrandpaWarpSync::Finished(Err(Error::Verifier(error))),
        }
    }
}

struct PostVerificationState<'a> {
    header: Header,
    chain_information_finality: ChainInformationFinality,
    genesis_chain_information: &'a ChainInformation,
}

/// Performing a grandpa warp sync network request is required to continue.
pub struct WarpSyncRequest<'a> {
    peer_index: usize,
    connected_peers: Vec<PeerId>,
    genesis_chain_information: &'a ChainInformation,
}

impl<'a> WarpSyncRequest<'a> {
    /// The peer to make a grandpa warp sync network request to.
    pub fn current_peer(&self) -> PeerId {
        self.connected_peers[self.peer_index].clone()
    }

    /// Submit a grandpa warp sync network response if the request succeeded or
    /// `None` if it did not.
    pub async fn handle_responste(
        self,
        response: Option<Vec<GrandpaWarpSyncResponseFragment>>,
    ) -> GrandpaWarpSync<'a> {
        let next_index = self.peer_index + 1;

        match response {
            Some(response_fragments) => GrandpaWarpSync::Verifier(Verifier {
                verifier: warp_sync::Verifier::new(
                    self.genesis_chain_information,
                    response_fragments,
                ),
                genesis_chain_information: self.genesis_chain_information,
            }),
            None if next_index < self.connected_peers.len() => {
                GrandpaWarpSync::WarpSyncRequest(Self {
                    peer_index: next_index,
                    connected_peers: self.connected_peers,
                    genesis_chain_information: self.genesis_chain_information,
                })
            }
            None => GrandpaWarpSync::Finished(Err(Error::AllRequestsFailed)),
        }
    }
}

/// Fetching the parameters for the virtual machine is required to continue.
pub struct VirtualMachineParamsGet<'a> {
    state: PostVerificationState<'a>,
}

impl<'a> VirtualMachineParamsGet<'a> {
    /// Set the code and heappages from storage using the keys `:code` and `:heappages`
    /// respectively. Also allows setting an execution hint for the virtual machine.
    pub fn inject_virtual_machine_params(
        self,
        code: impl AsRef<[u8]>,
        heap_pages: u64,
        exec_hint: ExecHint,
    ) -> GrandpaWarpSync<'a> {
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
