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

use crate::cli;

use futures::{channel::oneshot, prelude::*};
use smoldot::{
    chain, chain_spec,
    database::full_sqlite,
    header,
    identity::keystore,
    informant::HashDisplay,
    libp2p::{
        connection, multiaddr,
        peer_id::{self, PeerId},
    },
};
use std::{borrow::Cow, fs, io, iter, path::PathBuf, sync::Arc, thread, time::Duration};
use tracing::Instrument as _;

mod consensus_service;
mod database_thread;
mod jaeger_service;
mod json_rpc_service;
mod network_service;

/// Runs the node using the given configuration. Catches `SIGINT` signals and stops if one is
/// detected.
pub async fn run(cli_options: cli::CliOptionsRun) {
    // Determine the actual CLI output by replacing `Auto` with the actual value.
    let cli_output = if let cli::Output::Auto = cli_options.output {
        if atty::is(atty::Stream::Stderr) && cli_options.log.is_empty() {
            cli::Output::Informant
        } else {
            cli::Output::Logs
        }
    } else {
        cli_options.output
    };
    debug_assert!(!matches!(cli_output, cli::Output::Auto));

    // Setup the logging system of the binary.
    if !matches!(cli_output, cli::Output::None) {
        let mut env_filter = tracing_subscriber::filter::EnvFilter::new("DEBUG");
        if matches!(cli_output, cli::Output::Informant) {
            env_filter = env_filter.add_directive(tracing::Level::INFO.into()); // TODO: display infos/warnings in a nicer way ; in particular, immediately put the informant on top of warnings
        } else {
            for filter in cli_options.log {
                env_filter = env_filter.add_directive(filter);
            }
        }

        let builder = tracing_subscriber::fmt()
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc3339())
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::ENTER)
            .with_env_filter(env_filter)
            .with_writer(io::stdout);

        // Because calling `builder.json()` changes the type of `builder`, we do it at the end
        // and call `init()` at the same time.
        //
        // This registers a global process-wide subscriber.
        // While this is poor programming practices and we would prefer using a crate that doesn't
        // rely on global variables, the `tracing` crate is currently one of the best logging
        // crates in the Rust ecosystem at the time of writing of this comment.
        if matches!(cli_output, cli::Output::LogsJson) {
            builder.json().init();
        } else {
            builder
                .with_ansi(match cli_options.color {
                    cli::ColorChoice::Always => true,
                    cli::ColorChoice::Never => false,
                })
                .init();
        }
    }

    let chain_spec = {
        let json: Cow<[u8]> = match &cli_options.chain {
            cli::CliChain::Polkadot => (&include_bytes!("../../polkadot.json")[..]).into(),
            cli::CliChain::Kusama => (&include_bytes!("../../kusama.json")[..]).into(),
            cli::CliChain::Westend => (&include_bytes!("../../westend.json")[..]).into(),
            cli::CliChain::Custom(path) => {
                fs::read(path).expect("Failed to read chain specs").into()
            }
        };

        smoldot::chain_spec::ChainSpec::from_json_bytes(&json)
            .expect("Failed to decode chain specs")
    };

    // This warning message should be removed if/when the full node becomes mature.
    tracing::warn!(
        "Please note that this full node is experimental. It is not feature complete and is \
        known to panic often. Please report any panic you might encounter to \
        <https://github.com/paritytech/smoldot/issues>."
    );

    // TODO: don't unwrap?
    let genesis_chain_information = chain_spec.as_chain_information().unwrap().0;

    // If `chain_spec` define a parachain, also load the specs of the relay chain.
    let (relay_chain_spec, _parachain_id) =
        if let Some((relay_chain_name, parachain_id)) = chain_spec.relay_chain() {
            let json: Cow<[u8]> = match &cli_options.chain {
                cli::CliChain::Custom(parachain_path) => {
                    // TODO: this is a bit of a hack
                    let relay_chain_path = parachain_path
                        .parent()
                        .unwrap()
                        .join(format!("{}.json", relay_chain_name));
                    fs::read(&relay_chain_path)
                        .expect("Failed to read relay chain specs")
                        .into()
                }
                _ => panic!("Unexpected relay chain specified in hard-coded specs"),
            };

            let spec = smoldot::chain_spec::ChainSpec::from_json_bytes(&json)
                .expect("Failed to decode relay chain chain specs");

            // Make sure we're not accidentally opening the same chain twice, otherwise weird
            // interactions will happen.
            assert_ne!(spec.id(), chain_spec.id());

            (Some(spec), Some(parachain_id))
        } else {
            (None, None)
        };

    // TODO: don't unwrap?
    let relay_genesis_chain_information = relay_chain_spec
        .as_ref()
        .map(|relay_chain_spec| relay_chain_spec.as_chain_information().unwrap().0);

    let threads_pool = futures::executor::ThreadPool::builder()
        .name_prefix("tasks-pool-")
        .create()
        .unwrap();

    // Directory where we will store everything on the disk, such as the database, secret keys,
    // etc.
    let base_storage_directory =
        if let Some(base) = directories::ProjectDirs::from("io", "paritytech", "smoldot") {
            Some(base.data_dir().to_owned())
        } else {
            tracing::warn!(
                "Failed to fetch $HOME directory. Falling back to storing everything in memory, \
                meaning that everything will be lost when the node stops. If this is intended, \
                please make this explicit by passing the `--tmp` flag instead."
            );
            None
        };

    let (database, database_existed) = {
        // Directory supposed to contain the database.
        let db_path = base_storage_directory
            .as_ref()
            .map(|d| d.join(chain_spec.id()).join("database").to_owned());

        let (db, existed) = open_database(
            &chain_spec,
            &genesis_chain_information,
            db_path,
            matches!(cli_output, cli::Output::Informant),
        )
        .await;

        (Arc::new(database_thread::DatabaseThread::from(db)), existed)
    };

    let relay_chain_database = if let Some(relay_chain_spec) = &relay_chain_spec {
        let relay_db_path = base_storage_directory
            .as_ref()
            .map(|d| d.join(relay_chain_spec.id()).join("database").to_owned());

        Some(Arc::new(database_thread::DatabaseThread::from(
            open_database(
                relay_chain_spec,
                relay_genesis_chain_information.as_ref().unwrap(),
                relay_db_path,
                matches!(cli_output, cli::Output::Informant),
            )
            .await
            .0,
        )))
    } else {
        None
    };

    let database_finalized_block_hash = database
        .with_database(|db| db.finalized_block_hash().unwrap())
        .await;
    let database_finalized_block_number = header::decode(
        &database
            .with_database(move |db| {
                db.block_scale_encoded_header(&database_finalized_block_hash)
                    .unwrap()
                    .unwrap()
            })
            .await,
        chain_spec.block_number_bytes().into(),
    )
    .unwrap()
    .number;

    // TODO: remove; just for testing
    /*let metadata = smoldot::metadata::metadata_from_runtime_code(
        chain_spec
            .genesis_storage()
            .clone()
            .find(|(k, _)| *k == b":code")
            .unwrap().1,
            1024,
    )
    .unwrap();
    println!(
        "{:#?}",
        smoldot::metadata::decode(&metadata).unwrap()
    );*/

    // Determine which networking key to use.
    //
    // This is either passed as a CLI option, loaded from disk, or generated randomly.
    let noise_key = if let Some(node_key) = cli_options.libp2p_key {
        connection::NoiseKey::new(&node_key)
    } else if let Some(dir) = base_storage_directory.as_ref() {
        let path = dir.join("libp2p_ed25519_secret_key.secret");
        let noise_key = if path.exists() {
            let file_content =
                fs::read_to_string(&path).expect("failed to read libp2p secret key file content");
            let hex_decoded =
                hex::decode(file_content).expect("invalid libp2p secret key file content");
            let actual_key =
                <[u8; 32]>::try_from(hex_decoded).expect("invalid libp2p secret key file content");
            connection::NoiseKey::new(&actual_key)
        } else {
            let actual_key: [u8; 32] = rand::random();
            fs::write(&path, hex::encode(actual_key))
                .expect("failed to write libp2p secret key file");
            connection::NoiseKey::new(&actual_key)
        };
        // On Unix platforms, set the permission as 0o400 (only reading and by owner is permitted).
        // TODO: do something equivalent on Windows
        #[cfg(unix)]
        let _ = fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o400));
        noise_key
    } else {
        connection::NoiseKey::new(&rand::random())
    };

    let local_peer_id =
        peer_id::PublicKey::Ed25519(*noise_key.libp2p_public_ed25519_key()).into_peer_id();

    let genesis_block_hash = genesis_chain_information
        .finalized_block_header
        .hash(chain_spec.block_number_bytes().into());

    let jaeger_service = jaeger_service::JaegerService::new(jaeger_service::Config {
        tasks_executor: &mut |task| threads_pool.spawn_ok(task),
        service_name: local_peer_id.to_string(),
        jaeger_agent: cli_options.jaeger,
    })
    .await
    .unwrap();

    let (network_service, network_events_receivers) =
        network_service::NetworkService::new(network_service::Config {
            listen_addresses: cli_options.listen_addr,
            num_events_receivers: 2 + if relay_chain_database.is_some() { 1 } else { 0 },
            chains: iter::once(network_service::ChainConfig {
                protocol_id: chain_spec.protocol_id().to_owned(),
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
                database: database.clone(),
                has_grandpa_protocol: matches!(
                    genesis_chain_information.finality,
                    chain::chain_information::ChainInformationFinality::Grandpa { .. }
                ),
                genesis_block_hash,
                best_block: {
                    let block_number_bytes = chain_spec.block_number_bytes();
                    database
                        .with_database(move |database| {
                            let hash = database.finalized_block_hash().unwrap();
                            let header = database.block_scale_encoded_header(&hash).unwrap().unwrap();
                            let number = header::decode(&header, block_number_bytes.into(),).unwrap().number;
                            (number, hash)
                        })
                        .await
                },
                bootstrap_nodes: {
                    let mut list = Vec::with_capacity(
                        chain_spec.boot_nodes().len() + cli_options.additional_bootnode.len(),
                    );

                    for node in chain_spec.boot_nodes() {
                        match node {
                            chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                panic!("Failed to parse bootnode in chain specification: {}", raw)
                            }
                            chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                    Ok(a) => a,
                                    Err(_) => panic!(
                                        "Failed to parse bootnode in chain specification: {}",
                                        multiaddr
                                    ),
                                };
                                let peer_id = PeerId::from_bytes(peer_id.to_vec()).unwrap();
                                list.push((peer_id, multiaddr));
                            }
                        }
                    }

                    for bootnode in &cli_options.additional_bootnode {
                        list.push((bootnode.peer_id.clone(), bootnode.address.clone()));
                    }

                    list
                },
            })
            .chain(
                if let Some(relay_chains_specs) = &relay_chain_spec {
                    Some(network_service::ChainConfig {
                        protocol_id: relay_chains_specs.protocol_id().to_owned(),
                        block_number_bytes: usize::from(relay_chains_specs.block_number_bytes()),
                        database: relay_chain_database.clone().unwrap(),
                        has_grandpa_protocol: matches!(
                            relay_genesis_chain_information.as_ref().unwrap().finality,
                            chain::chain_information::ChainInformationFinality::Grandpa { .. }
                        ),
                        genesis_block_hash: relay_genesis_chain_information
                            .as_ref()
                            .unwrap()
                            .finalized_block_header
                            .hash(chain_spec.block_number_bytes().into(),),
                        best_block: relay_chain_database
                            .as_ref()
                            .unwrap()
                            .with_database({
                                let block_number_bytes = chain_spec.block_number_bytes();
                                move |db| {
                                    let hash = db.finalized_block_hash().unwrap();
                                    let header = db.block_scale_encoded_header(&hash).unwrap().unwrap();
                                    let number = header::decode(&header, block_number_bytes.into()).unwrap().number;
                                    (number, hash)
                                }
                            })
                            .await,
                        bootstrap_nodes: {
                            let mut list =
                                Vec::with_capacity(relay_chains_specs.boot_nodes().len());
                            for node in relay_chains_specs.boot_nodes() {
                                match node {
                                    chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                        panic!("Failed to parse bootnode in chain specification: {}", raw)
                                    }
                                    chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                        let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                            Ok(a) => a,
                                            Err(_) => panic!(
                                                "Failed to parse bootnode in chain specification: {}",
                                                multiaddr
                                            ),
                                        };
                                        let peer_id = PeerId::from_bytes(peer_id.to_vec()).unwrap();
                                        list.push((peer_id, multiaddr));
                                    }
                                }
                            }
                            list
                        },
                    })
                } else {
                    None
                }
                .into_iter(),
            )
            .collect(),
            noise_key,
            tasks_executor: &mut |task| threads_pool.spawn_ok(task),
            jaeger_service: jaeger_service.clone(),
        })
        .instrument(tracing::debug_span!("network-service-init"))
        .await
        .unwrap();

    let mut network_events_receivers = network_events_receivers.into_iter();

    let keystore = Arc::new({
        let mut keystore = keystore::Keystore::new(
            base_storage_directory
                .as_ref()
                .map(|path| path.join(chain_spec.id()).join("keys")),
            rand::random(),
        )
        .await
        .unwrap();
        for private_key in cli_options.keystore_memory {
            keystore.insert_sr25519_memory(keystore::KeyNamespace::all(), &private_key);
        }
        keystore
    });

    let consensus_service = consensus_service::ConsensusService::new(consensus_service::Config {
        tasks_executor: &mut |task| threads_pool.spawn_ok(task),
        genesis_block_hash,
        network_events_receiver: network_events_receivers.next().unwrap(),
        network_service: (network_service.clone(), 0),
        database,
        block_number_bytes: usize::from(chain_spec.block_number_bytes()),
        keystore,
        jaeger_service: jaeger_service.clone(),
        slot_duration_author_ratio: 43691_u16,
    })
    .instrument(tracing::debug_span!("consensus-service-init"))
    .await;

    let relay_chain_consensus_service = if let Some(relay_chain_database) = relay_chain_database {
        Some(
            consensus_service::ConsensusService::new(consensus_service::Config {
                tasks_executor: &mut |task| threads_pool.spawn_ok(task),
                genesis_block_hash: relay_genesis_chain_information
                    .as_ref()
                    .unwrap()
                    .finalized_block_header
                    .hash(usize::from(
                        relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                    )),
                network_events_receiver: network_events_receivers.next().unwrap(),
                network_service: (network_service.clone(), 1),
                database: relay_chain_database,
                block_number_bytes: usize::from(
                    relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                ),
                keystore: Arc::new(
                    keystore::Keystore::new(
                        base_storage_directory
                            .as_ref()
                            .map(|path| path.join(chain_spec.id()).join("keys")),
                        rand::random(),
                    )
                    .await
                    .unwrap(),
                ),
                jaeger_service, // TODO: consider passing a different jaeger service with a different service name
                slot_duration_author_ratio: 43691_u16,
            })
            .instrument(tracing::debug_span!("relay-chain-consensus-service-init"))
            .await,
        )
    } else {
        None
    };

    // Start the JSON-RPC service.
    // It only needs to be kept alive in order to function.
    //
    // Note that initialization can panic if, for example, the port is already occupied. It is
    // preferable to fail to start the node altogether rather than make the user believe that they
    // are connected to the JSON-RPC endpoint of the node while they are in reality connected to
    // something else.
    let _json_rpc_service = if let Some(bind_address) = cli_options.json_rpc_address.0 {
        let result = json_rpc_service::JsonRpcService::new(json_rpc_service::Config {
            tasks_executor: { &mut move |task| threads_pool.spawn_ok(task) },
            bind_address,
        })
        .await;

        Some(match result {
            Ok(service) => service,
            Err(err) => panic!("failed to initialize JSON-RPC endpoint: {}", err),
        })
    } else {
        None
    };

    /*let mut telemetry = {
        let endpoints = chain_spec
            .telemetry_endpoints()
            .map(|addr| (addr.as_ref().to_owned(), 0))
            .collect::<Vec<_>>();

        smoldot::telemetry::init_telemetry(smoldot::telemetry::TelemetryConfig {
            endpoints: smoldot::telemetry::TelemetryEndpoints::new(endpoints).unwrap(),
            wasm_external_transport: None,
            tasks_executor: {
                let threads_pool = threads_pool.clone();
                Box::new(move |task| threads_pool.spawn_obj_ok(From::from(task))) as Box<_>
            },
        })
    };*/

    tracing::info!(
        %local_peer_id, database_is_new = %!database_existed,
        finalized_block_hash = %HashDisplay(&database_finalized_block_hash),
        finalized_block_number = %database_finalized_block_number,
        "successful-initialization"
    );

    // Starting from here, a SIGINT (or equivalent) handler is setup. If the user does Ctrl+C,
    // a message will be sent on `ctrlc_rx`.
    // This should be performed after all the expensive initialization is done, as otherwise the
    // fact that initialization isn't interrupted by Ctrl+C could be frustrating for the user, but
    // also as soon as possible, as we want as many parts as possible to be cleanly destroyed on
    // Ctrl+C.
    let mut ctrlc_rx = {
        let (tx, rx) = oneshot::channel();
        let mut tx = Some(tx);
        ctrlc::set_handler(move || {
            if let Some(tx) = tx.take() {
                let _ = tx.send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
        rx.fuse()
    };

    let mut informant_timer = stream::once(future::ready(())).chain(
        stream::unfold((), move |_| {
            futures_timer::Delay::new(Duration::from_millis(100)).map(|_| Some(((), ())))
        })
        .map(|_| ()),
    );

    let mut telemetry_timer = stream::once(future::ready(())).chain(
        stream::unfold((), move |_| {
            futures_timer::Delay::new(Duration::from_secs(5)).map(|_| Some(((), ())))
        })
        .map(|_| ()),
    );

    let mut network_known_best = None;
    let mut main_network_events_receiver = network_events_receivers.next().unwrap();
    debug_assert!(network_events_receivers.next().is_none());

    loop {
        futures::select! {
            _ = informant_timer.next() => {
                if matches!(cli_output, cli::Output::Informant) {
                    // We end the informant line with a `\r` so that it overwrites itself every time.
                    // If any other line gets printed, it will overwrite the informant, and the
                    // informant will then print itself below, which is a fine behaviour.
                    let sync_state = consensus_service.sync_state().await;
                    eprint!("{}\r", smoldot::informant::InformantLine {
                        enable_colors: match cli_options.color {
                            cli::ColorChoice::Always => true,
                            cli::ColorChoice::Never => false,
                        },
                        chain_name: chain_spec.name(),
                        relay_chain: if let Some(relay_chain_spec) = &relay_chain_spec {
                            let relay_sync_state = relay_chain_consensus_service.as_ref().unwrap().sync_state().await;
                            Some(smoldot::informant::RelayChain {
                                chain_name: relay_chain_spec.name(),
                                best_number: relay_sync_state.best_block_number,
                            })
                        } else {
                            None
                        },
                        max_line_width: terminal_size::terminal_size().map_or(80, |(w, _)| w.0.into()),
                        num_peers: u64::try_from(network_service.num_peers(0).await)
                            .unwrap_or(u64::max_value()),
                        num_network_connections: u64::try_from(network_service.num_established_connections().await)
                            .unwrap_or(u64::max_value()),
                        best_number: sync_state.best_block_number,
                        finalized_number: sync_state.finalized_block_number,
                        best_hash: &sync_state.best_block_hash,
                        finalized_hash: &sync_state.finalized_block_hash,
                        network_known_best,
                    });
                }
            },

            network_event = main_network_events_receiver.next().fuse() => {
                // We expect the network events channel to never shut down.
                let network_event = network_event.unwrap();

                // Update `network_known_best`.
                match network_event {
                    network_service::Event::BlockAnnounce { chain_index: 0, header, .. } => {
                        match network_known_best {
                            Some(n) if n >= header.number => {},
                            _ => network_known_best = Some(header.number),
                        }
                    }
                    network_service::Event::Connected { chain_index: 0, best_block_number, .. } => {
                        match network_known_best {
                            Some(n) if n >= best_block_number => {},
                            _ => network_known_best = Some(best_block_number),
                        }
                    }
                    _ => {}
                }
            }

            /*telemetry_event = telemetry.next_event().fuse() => {
                telemetry.send(smoldot::telemetry::message::TelemetryMessage::SystemConnected(smoldot::telemetry::message::SystemConnected {
                    chain: chain_spec.name().to_owned().into_boxed_str(),
                    name: String::from("✨ Smoldot ✨").into_boxed_str(),  // TODO: node name
                    implementation: String::from("Secret projet 🤫").into_boxed_str(),  // TODO:
                    version: String::from(env!("CARGO_PKG_VERSION")).into_boxed_str(),
                    validator: None,
                    network_id: None, // TODO: Some(service.local_peer_id().to_base58().into_boxed_str()),
                }));
            },*/

            _ = telemetry_timer.next() => {
                /*let sync_state = sync_state.lock().await.clone();

                // Some of the fields below are set to `None` because there is no plan to
                // implement reporting accurate metrics about the node.
                telemetry.send(smoldot::telemetry::message::TelemetryMessage::SystemInterval(smoldot::telemetry::message::SystemInterval {
                    stats: smoldot::telemetry::message::NodeStats {
                        peers: network_state.num_network_connections.load(Ordering::Relaxed),
                        txcount: 0,  // TODO:
                    },
                    memory: None,
                    cpu: None,
                    bandwidth_upload: Some(0.0), // TODO:
                    bandwidth_download: Some(0.0), // TODO:
                    finalized_height: Some(sync_state.finalized_block_number),
                    finalized_hash: Some(sync_state.finalized_block_hash.into()),
                    block: smoldot::telemetry::message::Block {
                        hash: sync_state.best_block_hash.into(),
                        height: sync_state.best_block_number,
                    },
                    used_state_cache_size: None,
                    used_db_cache_size: None,
                    disk_read_per_sec: None,
                    disk_write_per_sec: None,
                }));*/
            },

            _ = ctrlc_rx => {
                if matches!(cli_output, cli::Output::Informant) {
                    // Adding a new line after the informant so that the user's shell doesn't
                    // overwrite it.
                    eprintln!("");
                }

                return
            },
        }
    }
}

/// Opens the database from the file system, or create a new database if none is found.
///
/// If `db_path` is `None`, open the database in memory instead.
///
/// The returned boolean is `true` if the database existed before.
///
/// # Panic
///
/// Panics if the database can't be open. This function is expected to be called from the `main`
/// function.
///
#[tracing::instrument(level = "trace", skip(chain_spec, show_progress))]
async fn open_database(
    chain_spec: &chain_spec::ChainSpec,
    genesis_chain_information: &chain::chain_information::ChainInformation,
    db_path: Option<PathBuf>,
    show_progress: bool,
) -> (full_sqlite::SqliteFullDatabase, bool) {
    // The `unwrap()` here can panic for example in case of access denied.
    match background_open_database(
        db_path.clone(),
        chain_spec.block_number_bytes().into(),
        show_progress,
    )
    .await
    .unwrap()
    {
        // Database already exists and contains data.
        full_sqlite::DatabaseOpen::Open(database) => {
            if database.block_hash_by_number(0).unwrap().next().unwrap()
                != genesis_chain_information
                    .finalized_block_header
                    .hash(chain_spec.block_number_bytes().into())
            {
                panic!("Mismatch between database and chain specification. Shutting down node.");
            }

            (database, true)
        }

        // The database doesn't exist or is empty.
        full_sqlite::DatabaseOpen::Empty(empty) => {
            // The finalized block is the genesis block. As such, it has an empty body and
            // no justification.
            let database = empty
                .initialize(
                    genesis_chain_information,
                    iter::empty(),
                    None,
                    chain_spec
                        .genesis_storage()
                        .into_genesis_items()
                        .unwrap() // TODO: return error instead
                        .iter(),
                )
                .unwrap();
            (database, false)
        }
    }
}

/// Since opening the database can take a long time, this utility function performs this operation
/// in the background while showing a small progress bar to the user.
///
/// If `path` is `None`, the database is opened in memory.
#[tracing::instrument(level = "trace", skip(show_progress))]
async fn background_open_database(
    path: Option<PathBuf>,
    block_number_bytes: usize,
    show_progress: bool,
) -> Result<full_sqlite::DatabaseOpen, full_sqlite::InternalError> {
    let (tx, rx) = oneshot::channel();
    let mut rx = rx.fuse();

    let thread_spawn_result = thread::Builder::new().name("database-open".into()).spawn({
        let path = path.clone();
        move || {
            let result = full_sqlite::open(full_sqlite::Config {
                block_number_bytes,
                ty: if let Some(path) = &path {
                    full_sqlite::ConfigTy::Disk(path)
                } else {
                    full_sqlite::ConfigTy::Memory
                },
            });
            let _ = tx.send(result);
        }
    });

    // Fall back to opening the database on the same thread if the thread spawn failed.
    if thread_spawn_result.is_err() {
        return full_sqlite::open(full_sqlite::Config {
            block_number_bytes,
            ty: if let Some(path) = &path {
                full_sqlite::ConfigTy::Disk(path)
            } else {
                full_sqlite::ConfigTy::Memory
            },
        });
    }

    let mut progress_timer = stream::unfold((), move |_| {
        futures_timer::Delay::new(Duration::from_millis(200)).map(|_| Some(((), ())))
    })
    .map(|_| ());

    let mut next_progress_icon = ['-', '\\', '|', '/'].iter().copied().cycle();

    loop {
        futures::select! {
            res = rx => return res.unwrap(),
            _ = progress_timer.next() => {
                if show_progress {
                    eprint!("    Opening database... {}\r", next_progress_icon.next().unwrap());
                }
            }
        }
    }
}
