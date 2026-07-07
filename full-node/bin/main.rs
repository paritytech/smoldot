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

#![deny(rustdoc::broken_intra_doc_links)]
// TODO: #![deny(unused_crate_dependencies)] doesn't work because some deps are used only by the library, figure if this can be fixed?

use std::{
    fs, io,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod cli;

fn main() {
    smol::block_on(async_main())
}

async fn async_main() {
    match <cli::CliOptions as clap::Parser>::parse().command {
        cli::CliOptionsCommand::Run(r) => run(*r).await,
        cli::CliOptionsCommand::Blake264BitsHash(opt) => {
            let hash = blake2_rfc::blake2b::blake2b(8, &[], opt.payload.as_bytes());
            println!("0x{}", hex::encode(hash));
        }
        cli::CliOptionsCommand::Blake2256BitsHash(opt) => {
            let content = fs::read(opt.file).expect("Failed to read file content");
            let hash = blake2_rfc::blake2b::blake2b(32, &[], &content);
            println!("0x{}", hex::encode(hash));
        }
    }
}

async fn run(cli_options: cli::CliOptionsRun) {
    // Determine the actual CLI output by replacing `Auto` with the actual value.
    let cli_output = if let cli::Output::Auto = cli_options.output {
        if io::IsTerminal::is_terminal(&io::stderr()) && cli_options.log_level.is_none() {
            cli::Output::Informant
        } else {
            cli::Output::Logs
        }
    } else {
        cli_options.output
    };
    debug_assert!(!matches!(cli_output, cli::Output::Auto));

    // Setup the logging system of the binary.
    let log_callback: Arc<dyn smoldot_full_node::LogCallback + Send + Sync> = match cli_output {
        cli::Output::None => Arc::new(|_level, _message| {}),
        cli::Output::Informant | cli::Output::Logs => {
            let color_choice = cli_options.color.clone();
            let log_level = cli_options.log_level.clone().unwrap_or(
                if matches!(cli_output, cli::Output::Informant) {
                    cli::LogLevel::Info
                } else {
                    cli::LogLevel::Debug
                },
            );

            Arc::new(move |level, message| {
                match (&level, &log_level) {
                    (_, cli::LogLevel::Off) => return,
                    (
                        smoldot_full_node::LogLevel::Warn
                        | smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Error,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Warn,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Debug | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Info,
                    ) => return,
                    (smoldot_full_node::LogLevel::Trace, cli::LogLevel::Debug) => return,
                    _ => {}
                }

                let when = humantime::format_rfc3339_millis(SystemTime::now());

                let level_str = match (level, &color_choice) {
                    (smoldot_full_node::LogLevel::Trace, cli::ColorChoice::Never) => "trace",
                    (smoldot_full_node::LogLevel::Trace, cli::ColorChoice::Always) => {
                        "\x1b[36mtrace\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Debug, cli::ColorChoice::Never) => "debug",
                    (smoldot_full_node::LogLevel::Debug, cli::ColorChoice::Always) => {
                        "\x1b[34mdebug\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Info, cli::ColorChoice::Never) => "info",
                    (smoldot_full_node::LogLevel::Info, cli::ColorChoice::Always) => {
                        "\x1b[32minfo\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Warn, cli::ColorChoice::Never) => "warn",
                    (smoldot_full_node::LogLevel::Warn, cli::ColorChoice::Always) => {
                        "\x1b[33;1mwarn\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Error, cli::ColorChoice::Never) => "error",
                    (smoldot_full_node::LogLevel::Error, cli::ColorChoice::Always) => {
                        "\x1b[31;1merror\x1b[0m"
                    }
                };

                eprintln!("[{}] [{}] {}", when, level_str, message);
            }) as Arc<dyn smoldot_full_node::LogCallback + Send + Sync>
        }
        cli::Output::LogsJson => {
            let log_level = cli_options
                .log_level
                .clone()
                .unwrap_or(cli::LogLevel::Debug);
            Arc::new(move |level, message| {
                match (&level, &log_level) {
                    (_, cli::LogLevel::Off) => return,
                    (
                        smoldot_full_node::LogLevel::Warn
                        | smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Error,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Warn,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Debug | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Info,
                    ) => return,
                    (smoldot_full_node::LogLevel::Trace, cli::LogLevel::Debug) => return,
                    _ => {}
                }

                #[derive(serde::Serialize)]
                struct Record {
                    timestamp: u128,
                    level: &'static str,
                    message: String,
                }

                let mut lock = std::io::stderr().lock();
                if serde_json::to_writer(
                    &mut lock,
                    &Record {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0),
                        level: match level {
                            smoldot_full_node::LogLevel::Trace => "trace",
                            smoldot_full_node::LogLevel::Debug => "debug",
                            smoldot_full_node::LogLevel::Info => "info",
                            smoldot_full_node::LogLevel::Warn => "warn",
                            smoldot_full_node::LogLevel::Error => "error",
                        },
                        message,
                    },
                )
                .is_ok()
                {
                    let _ = io::Write::write_all(&mut lock, b"\n");
                }
            })
        }
        cli::Output::Auto => unreachable!(), // Handled above.
    };

    let chain_spec =
        fs::read(&cli_options.path_to_chain_spec).expect("Failed to read chain specification");
    let parsed_chain_spec = {
        smoldot::chain_spec::ChainSpec::from_json_bytes(&chain_spec)
            .expect("Failed to decode chain specification")
    };

    // Directory where we will store everything on the disk, such as the database, secret keys,
    // etc.
    let base_storage_directory = if cli_options.tmp {
        None
    } else if let Some(base) = directories::ProjectDirs::from("io", "smoldot", "smoldot") {
        Some(base.data_dir().to_owned())
    } else {
        log_callback.log(
            smoldot_full_node::LogLevel::Warn,
            "Failed to fetch $HOME directory. Falling back to storing everything in memory, \
                meaning that everything will be lost when the node stops. If this is intended, \
                please make this explicit by passing the `--tmp` flag instead."
                .to_string(),
        );
        None
    };

    // Create the directory if necessary.
    if let Some(base_storage_directory) = base_storage_directory.as_ref() {
        fs::create_dir_all(base_storage_directory.join(parsed_chain_spec.id())).unwrap();
    }
    // Directory supposed to contain the database.
    let sqlite_database_path = base_storage_directory
        .as_ref()
        .map(|d| d.join(parsed_chain_spec.id()).join("database"));
    // Directory supposed to contain the keystore.
    let keystore_path = base_storage_directory
        .as_ref()
        .map(|path| path.join(parsed_chain_spec.id()).join("keys"));

    // Build the relay chain information if relevant.
    let (relay_chain, relay_chain_name) =
        if let Some((relay_chain_name, _parachain_id)) = parsed_chain_spec.relay_chain() {
            let spec_json = {
                let relay_chain_path = cli_options
                    .path_to_chain_spec
                    .parent()
                    .unwrap()
                    .join(format!("{relay_chain_name}.json"));
                fs::read(&relay_chain_path).expect("Failed to read relay chain specification")
            };

            let parsed_relay_spec = smoldot::chain_spec::ChainSpec::from_json_bytes(&spec_json)
                .expect("Failed to decode relay chain chain specs");

            // Make sure we're not accidentally opening the same chain twice, otherwise weird
            // interactions will happen.
            assert_ne!(parsed_relay_spec.id(), parsed_chain_spec.id());

            // Create the directory if necessary.
            if let Some(base_storage_directory) = base_storage_directory.as_ref() {
                fs::create_dir_all(base_storage_directory.join(parsed_relay_spec.id())).unwrap();
            }

            let cfg = smoldot_full_node::ChainConfig {
                chain_spec: spec_json.into(),
                additional_bootnodes: Vec::new(),
                keystore_memory: Vec::new(),
                sqlite_database_path: base_storage_directory.as_ref().map(|d| {
                    d.join(parsed_relay_spec.id())
                        .join("database")
                        .join("database.sqlite")
                }),
                sqlite_cache_size: cli_options.relay_chain_database_cache_size.0,
                keystore_path: base_storage_directory
                    .as_ref()
                    .map(|path| path.join(parsed_relay_spec.id()).join("keys")),
                json_rpc_listen: None,
            };

            (Some(cfg), Some(relay_chain_name.to_owned()))
        } else {
            (None, None)
        };

    // Determine which networking key to use.
    //
    // This is either passed as a CLI option, loaded from disk, or generated randomly.
    // TODO: move this code to `/lib/src/identity`?
    let libp2p_key = if let Some(node_key) = cli_options.libp2p_key {
        node_key
    } else if let Some(dir) = base_storage_directory.as_ref() {
        let path = dir.join("libp2p_ed25519_secret_key.secret");
        let libp2p_key = if path.exists() {
            let file_content = zeroize::Zeroizing::new(
                fs::read_to_string(&path).expect("failed to read libp2p secret key file content"),
            );
            let mut hex_decoded = Box::new([0u8; 32]);
            hex::decode_to_slice(file_content, &mut *hex_decoded)
                .expect("invalid libp2p secret key file content");
            hex_decoded
        } else {
            let mut actual_key = Box::new([0u8; 32]);
            rand::Fill::try_fill(&mut *actual_key, &mut rand::thread_rng()).unwrap();
            let mut hex_encoded = Box::new([0; 64]);
            hex::encode_to_slice(*actual_key, &mut *hex_encoded).unwrap();
            fs::write(&path, *hex_encoded).expect("failed to write libp2p secret key file");
            zeroize::Zeroize::zeroize(&mut *hex_encoded);
            actual_key
        };
        // On Unix platforms, set the permission as 0o400 (only reading and by owner is permitted).
        // TODO: do something equivalent on Windows
        #[cfg(unix)]
        let _ = fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o400));
        libp2p_key
    } else {
        let mut key = Box::new([0u8; 32]);
        rand::Fill::try_fill(&mut *key, &mut rand::thread_rng()).unwrap();
        key
    };

    // Create an executor where tasks are going to be spawned onto.
    let executor = Arc::new(smol::Executor::new());
    for n in 0..thread::available_parallelism()
        .map(|n| n.get() - 1)
        .unwrap_or(3)
    {
        let executor = executor.clone();

        let spawn_result = thread::Builder::new()
            .name(format!("tasks-pool-{}", n))
            .spawn(move || smol::block_on(executor.run(smol::future::pending::<()>())));

        // Ignore a failure to spawn a thread, as we're going to run tasks on the current thread
        // later down this function.
        if let Err(err) = spawn_result {
            log_callback.log(
                smoldot_full_node::LogLevel::Warn,
                format!("tasks-pool-thread-spawn-failure; err={err}"),
            );
        }
    }

    // Print some general information.
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "smoldot full node".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "Copyright (C) 2023  Pierre Krieger.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "This program comes with ABSOLUTELY NO WARRANTY.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "This is free software, and you are welcome to redistribute it under certain conditions."
            .to_string(),
    );

    // This warning message should be removed if/when the full node becomes mature.
    log_callback.log(
        smoldot_full_node::LogLevel::Warn,
        "Please note that this full node is experimental. It is not feature complete and is \
        known to panic often. Please report any panic you might encounter to \
        <https://github.com/paritytech/smoldot/issues>."
            .to_string(),
    );

    let client_init_result = smoldot_full_node::start(smoldot_full_node::Config {
        chain: smoldot_full_node::ChainConfig {
            chain_spec: chain_spec.into(),
            additional_bootnodes: cli_options
                .additional_bootnode
                .iter()
                .map(|cli::Bootnode { address, peer_id }| (peer_id.clone(), address.clone()))
                .collect(),
            keystore_memory: cli_options.keystore_memory,
            sqlite_database_path,
            sqlite_cache_size: cli_options.database_cache_size.0,
            keystore_path,
            json_rpc_listen: if let Some(address) = cli_options.json_rpc_address.0 {
                Some(smoldot_full_node::JsonRpcListenConfig {
                    address,
                    max_json_rpc_clients: cli_options.json_rpc_max_clients,
                })
            } else {
                None
            },
        },
        relay_chain,
        libp2p_key,
        listen_addresses: cli_options.listen_addr,
        tasks_executor: {
            let executor = executor.clone();
            Arc::new(move |task| executor.spawn(task).detach())
        },
        log_callback: log_callback.clone(),
        jaeger_agent: cli_options.jaeger,
    })
    .await;

    let client = match client_init_result {
        Ok(c) => c,
        Err(err) => {
            log_callback.log(
                smoldot_full_node::LogLevel::Error,
                format!("Failed to initialize client: {}", err),
            );
            panic!("Failed to initialize client: {}", err);
        }
    };

    if let Some(addr) = client.json_rpc_server_addr() {
        log_callback.log(
            smoldot_full_node::LogLevel::Info,
            format!(
                "JSON-RPC server listening on {addr}. Visit \
                <https://ipfs.io/ipns/dotapps.io/?rpc=ws%3A%2F%2F{addr}> in order to \
                interact with the node."
            ),
        );
    }

    // Starting from here, a SIGINT (or equivalent) handler is set up. If the user does Ctrl+C,
    // an event will be triggered on `ctrlc_detected`.
    // This should be performed after all the expensive initialization is done, as otherwise these
    // expensive initializations aren't interrupted by Ctrl+C, which could be frustrating for the
    // user.
    let ctrlc_detected = {
        let event = event_listener::Event::new();
        let listen = event.listen();
        if let Err(err) = ctrlc::set_handler(move || {
            event.notify(usize::MAX);
        }) {
            // It is not critical to fail to setup the Ctrl-C handler.
            log_callback.log(
                smoldot_full_node::LogLevel::Warn,
                format!("ctrlc-handler-setup-fail; err={err}"),
            );
        }
        listen
    };

    // Spawn a task that prints the informant at a regular interval.
    // The interval is fast enough that the informant should be visible roughly at any time,
    // even if the terminal is filled with logs.
    // Note that this task also holds the smoldot `client` alive, and thus we spawn it even if
    // the informant is disabled.
    let main_task = executor.spawn({
        let show_informant = matches!(cli_output, cli::Output::Informant);
        let informant_colors = match cli_options.color {
            cli::ColorChoice::Always => true,
            cli::ColorChoice::Never => false,
        };

        async move {
            let mut informant_timer = if show_informant {
                smol::Timer::after(Duration::new(0, 0))
            } else {
                smol::Timer::never()
            };

            loop {
                informant_timer =
                    smol::Timer::at(informant_timer.await + Duration::from_millis(100));

                // We end the informant line with a `\r` so that it overwrites itself
                // every time. If any other line gets printed, it will overwrite the
                // informant, and the informant will then print itself below, which is
                // a fine behaviour.
                let sync_state = client.sync_state().await;
                eprint!(
                    "{}\r",
                    smoldot::informant::InformantLine {
                        enable_colors: informant_colors,
                        chain_name: parsed_chain_spec.name(),
                        relay_chain: client.relay_chain_sync_state().await.map(
                            |relay_sync_state| smoldot::informant::RelayChain {
                                chain_name: relay_chain_name.as_ref().unwrap(),
                                best_number: relay_sync_state.best_block_number,
                            }
                        ),
                        max_line_width: terminal_size::terminal_size()
                            .map_or(80, |(w, _)| w.0.into()),
                        num_peers: client.num_peers().await,
                        num_network_connections: client.num_network_connections().await,
                        best_number: sync_state.best_block_number,
                        finalized_number: sync_state.finalized_block_number,
                        best_hash: &sync_state.best_block_hash,
                        finalized_hash: &sync_state.finalized_block_hash,
                        network_known_best: client.network_known_best().await,
                    }
                );
            }
        }
    });

    // Now run all the tasks that have been spawned.
    executor.run(ctrlc_detected).await;

    // Add a new line after the informant so that the user's shell doesn't
    // overwrite it.
    if matches!(cli_output, cli::Output::Informant) {
        eprintln!();
    }

    // After `ctrlc_detected` has triggered, we destroy `main_task`, which cancels it and destroys
    // the smoldot client.
    drop::<smol::Task<_>>(main_task);

    // TODO: consider running the executor until all tasks shut down gracefully; unfortunately this currently hangs
}
