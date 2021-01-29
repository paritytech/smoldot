use crate::chain::chain_information::{
    babe_fetch_epoch, BabeEpochInformation, ChainInformation, ChainInformationConsensus,
    ChainInformationFinality,
};
use crate::executor::host::HostVmPrototype;
use crate::executor::host::NewErr;
use crate::executor::vm::ExecHint;
use crate::finality::grandpa::warp_sync::{self, Next};
use crate::finality::justification::verify;
use crate::header::Header;
use crate::libp2p::PeerId;
use crate::network::service::ChainNetwork;
use crate::network::service::GrandpaWarpSyncRequestError;
use core::ops::{Add, Sub};
use core::time::Duration;

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
pub struct Config<'a, TNow, TPeer, TConn> {
    pub connected_peers: Vec<PeerId>,
    pub network: &'a ChainNetwork<TNow, TPeer, TConn>,
    pub now: TNow,
    pub chain_index: usize,
    pub begin_hash: [u8; 32],
    pub genesis_chain_information: &'a ChainInformation,
}

/// Starts syncing via grandpa warp sync.
pub fn grandpa_warp_sync<TNow, TPeer, TConn>(
    config: Config<'_, TNow, TPeer, TConn>,
) -> GrandpaWarpSync<TNow, TPeer, TConn>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    GrandpaWarpSync::WarpSyncRequest(WarpSyncRequest {
        peer_index: 0,
        connected_peers: config.connected_peers,
        network: config.network,
        now: config.now,
        chain_index: config.chain_index,
        begin_hash: config.begin_hash,
        genesis_chain_information: config.genesis_chain_information,
    })
}

/// The grandpa warp sync state machine.
pub enum GrandpaWarpSync<'a, TNow, TPeer, TConn> {
    /// Warp syncing is over.
    Finished(Result<(ChainInformation, HostVmPrototype), Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet<'a>),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey<'a>),
    /// Verifying the warp sync response is required to continue.
    Verifier(Verifier<'a>),
    /// Performing a network request is required to continue.
    WarpSyncRequest(WarpSyncRequest<'a, TNow, TPeer, TConn>),
    /// Fetching the parameters for the virtual machine is required to continue.
    VirtualMachineParamsGet(VirtualMachineParamsGet<'a>),
}

impl<'a, TNow, TPeer, TConn> GrandpaWarpSync<'a, TNow, TPeer, TConn> {
    fn from_babe_fetch_epoch_query(
        inner: babe_fetch_epoch::Query,
        fetched_current_epoch: Option<BabeEpochInformation>,
        state: PostVerificationState<'a>,
    ) -> Self {
        match (inner, fetched_current_epoch) {
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
    pub fn inject_value<TNow, TPeer, TConn>(
        self,
        value: Option<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> GrandpaWarpSync<'a, TNow, TPeer, TConn> {
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
    pub fn inject_key<TNow, TPeer, TConn>(
        self,
        key: Option<impl AsRef<[u8]>>,
    ) -> GrandpaWarpSync<'a, TNow, TPeer, TConn> {
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
    pub fn next<TNow, TPeer, TConn>(self) -> GrandpaWarpSync<'a, TNow, TPeer, TConn> {
        match self.verifier.next() {
            Ok(Next::NotFinished(next_verifier)) => GrandpaWarpSync::Verifier(Self {
                verifier: next_verifier,
                genesis_chain_information: self.genesis_chain_information,
            }),
            Ok(Next::Success {
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

/// Performing a network request is required to continue.
pub struct WarpSyncRequest<'a, TNow, TPeer, TConn> {
    peer_index: usize,
    connected_peers: Vec<PeerId>,

    now: TNow,
    network: &'a ChainNetwork<TNow, TPeer, TConn>,
    chain_index: usize,
    begin_hash: [u8; 32],
    genesis_chain_information: &'a ChainInformation,
}

impl<'a, TNow, TPeer, TConn> WarpSyncRequest<'a, TNow, TPeer, TConn>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
{
    /// Peform the grandpa warp sync request. Returns an optional error if a
    /// request failed.
    pub async fn request(
        self,
    ) -> (
        GrandpaWarpSync<'a, TNow, TPeer, TConn>,
        Option<GrandpaWarpSyncRequestError>,
    ) {
        let peer = self.connected_peers[self.peer_index].clone();

        let response = self
            .network
            .grandpa_warp_sync_request(self.now.clone(), peer, self.chain_index, self.begin_hash)
            .await;

        let next_index = self.peer_index + 1;

        match response {
            Ok(response_fragments) => (
                GrandpaWarpSync::Verifier(Verifier {
                    verifier: warp_sync::Verifier::new(
                        self.genesis_chain_information,
                        response_fragments,
                    ),
                    genesis_chain_information: self.genesis_chain_information,
                }),
                None,
            ),
            Err(error) if next_index < self.connected_peers.len() => (
                GrandpaWarpSync::WarpSyncRequest(Self {
                    peer_index: next_index,
                    connected_peers: self.connected_peers,
                    now: self.now,
                    network: self.network,
                    chain_index: self.chain_index,
                    begin_hash: self.begin_hash,
                    genesis_chain_information: self.genesis_chain_information,
                }),
                Some(error),
            ),
            Err(error) => (
                GrandpaWarpSync::Finished(Err(Error::AllRequestsFailed)),
                Some(error),
            ),
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
    pub fn inject_virtual_machine_params<TNow, TPeer, TConn>(
        self,
        code: impl AsRef<[u8]>,
        heap_pages: u64,
        exec_hint: ExecHint,
    ) -> GrandpaWarpSync<'a, TNow, TPeer, TConn> {
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
