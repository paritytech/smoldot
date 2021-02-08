use crate::network_service;
use futures::{channel::mpsc, future, FutureExt, StreamExt};
use smoldot::{
    chain::{
        chain_information::ChainInformation,
        sync::grandpa_warp_sync::{self, GrandpaWarpSync},
    },
    chain_spec::ChainSpec,
    executor::{host::HostVmPrototype, vm::ExecHint},
    libp2p,
};
use std::{iter, sync::Arc};

#[derive(Debug)]
pub enum Error {
    GrandpaWarpSync(grandpa_warp_sync::Error),
    StorageQuery(network_service::StorageQueryError),
}

pub struct Config {
    pub start_chain_information: ChainInformation,
    pub network_service: Arc<network_service::NetworkService>,
    pub network_event_receiver: mpsc::Receiver<network_service::Event>,
}

pub async fn grandpa_warp_sync(
    config: Config,
) -> Result<(ChainInformation, HostVmPrototype), Error> {
    let Config {
        start_chain_information,
        network_service,
        mut network_event_receiver,
    } = config;

    let mut sync =
        grandpa_warp_sync::grandpa_warp_sync::<libp2p::PeerId>(grandpa_warp_sync::Config {
            start_chain_information,
            sources_capacity: 32,
        });

    let mut warp_sync_requests = 0_u32;

    loop {
        match sync {
            GrandpaWarpSync::WaitingForSources(waiting_for_sources) => {
                log::info!("Waiting for peers");

                let peer = (&mut network_event_receiver)
                    .filter_map(|event| {
                        future::ready(match event {
                            network_service::Event::Connected { peer_id, .. } => Some(peer_id),
                            _ => None,
                        })
                    })
                    .next()
                    .await
                    .unwrap();

                sync = waiting_for_sources.add_source(peer);
            }
            GrandpaWarpSync::WarpSyncRequest(warp_sync_request) => {
                sync = handle_warp_sync_request(
                    warp_sync_request,
                    &mut network_event_receiver,
                    network_service.clone(),
                )
                .await;

                warp_sync_requests += 1;
            }
            GrandpaWarpSync::Verifier(verifier) => {
                sync = verifier.next();
            }
            GrandpaWarpSync::VirtualMachineParamsGet(virtual_machine_params_get) => {
                let header = virtual_machine_params_get.warp_sync_header();
                log::info!(
                    "Warp syncing up to block number {}, made {} total warp sync requests.",
                    header.number,
                    warp_sync_requests
                );

                let mut results = network_service
                    .clone()
                    .storage_query(
                        &header.hash(),
                        &header.state_root,
                        iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
                    )
                    .await
                    .map_err(Error::StorageQuery)?;

                let heappages = results.remove(1);
                let code = results.remove(0);

                sync = virtual_machine_params_get.set_virtual_machine_params(
                    code,
                    heappages,
                    ExecHint::Oneshot,
                );
            }
            GrandpaWarpSync::StorageGet(storage_get) => {
                let header = storage_get.warp_sync_header();
                let key = storage_get.key_as_vec();

                let mut results = network_service
                    .clone()
                    .storage_query(&header.hash(), &header.state_root, iter::once(&key))
                    .await
                    .map_err(Error::StorageQuery)?;

                let value = results.remove(0);

                sync = storage_get.inject_value(value.map(|value| iter::once(value)));
            }
            GrandpaWarpSync::NextKey(_) => {
                unimplemented!()
            }
            GrandpaWarpSync::Finished(result) => return result.map_err(Error::GrandpaWarpSync),
        }
    }
}

async fn handle_warp_sync_request(
    mut warp_sync_request: grandpa_warp_sync::WarpSyncRequest<libp2p::PeerId>,
    network_event_receiver: &mut mpsc::Receiver<network_service::Event>,
    network_service: Arc<network_service::NetworkService>,
) -> GrandpaWarpSync<libp2p::PeerId> {
    while let Some(Some(event)) = network_event_receiver.next().now_or_never() {
        match event {
            network_service::Event::Connected { peer_id, .. } => {
                warp_sync_request.add_source(peer_id);
            }
            network_service::Event::Disconnected(peer_id) => {
                return warp_sync_request.remove_source(peer_id);
            }
            network_service::Event::BlockAnnounce { .. } => {}
        }
    }

    let current_peer = warp_sync_request.current_source().clone();
    let start_block_hash = warp_sync_request.start_block_hash();
    let response = network_service
        .grandpa_warp_sync_request(current_peer, start_block_hash)
        .await;

    if let Err(error) = response.as_ref() {
        log::warn!("{}", error);
    }

    let mut response = response.ok();

    if response
        .as_ref()
        .map(|response| response.is_empty())
        .unwrap_or(false)
    {
        log::warn!("Got a warp sync response that's empty");
    }

    warp_sync_request.handle_response(response)
}
