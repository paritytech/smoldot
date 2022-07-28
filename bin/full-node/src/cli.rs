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

//! Provides the [`CliOptions`] struct that contains all the CLI options that can be passed to the
//! binary.
//!
//! See the documentation of the [`clap`] crate in order to learn more.
//!
//! # Example
//!
//! ```no_run
//! use clap::StructOpt as _;
//! let cli_options = full_node::CliOptions::from_args();
//! println!("Quiet: {:?}", cli_options.quiet);
//! ```
//!
// TODO: I believe this example isn't tested ^ which kills the point of having it

use smoldot::{
    identity::seed_phrase,
    libp2p::{
        multiaddr::{Multiaddr, ProtocolRef},
        PeerId,
    },
};
use std::{net::SocketAddr, path::PathBuf};

// Note: the doc-comments applied to this struct and its field are visible when the binary is
// started with `--help`.

#[derive(Debug, clap::StructOpt)]
#[clap(about, author, version)]
pub enum CliOptions {
    /// Connects to the chain and synchronizes the local database with the network.
    Run(Box<CliOptionsRun>),
    /// Computes the 64 bits BLAKE2 hash of a string payload and prints the hexadecimal-encoded hash.
    #[structopt(name = "blake2-64bits-hash")]
    Blake264BitsHash(CliOptionsBlake264Hash),
}

#[derive(Debug, clap::StructOpt)]
pub struct CliOptionsRun {
    /// Chain to connect to ("Polkadot", "Kusama", "Westend", or a file path).
    #[structopt(long, default_value = "polkadot")]
    pub chain: CliChain,
    /// Output to stdout: auto, none, informant, logs, logs-json.
    #[structopt(long, default_value = "auto")]
    pub output: Output,
    /// Log filter. Example: `foo=trace`
    #[structopt(long)]
    pub log: Vec<tracing_subscriber::filter::Directive>,
    /// Coloring: auto, always, never
    #[structopt(long, default_value = "auto")]
    pub color: ColorChoice,
    /// Ed25519 private key of network identity (as a seed phrase).
    #[structopt(long, parse(try_from_str = decode_ed25519_private_key))]
    pub libp2p_key: Option<[u8; 32]>,
    /// `Multiaddr` to listen on.
    #[structopt(long, parse(try_from_str = decode_multiaddr))]
    pub listen_addr: Vec<Multiaddr>,
    /// `Multiaddr` of an additional node to try to connect to on startup.
    #[structopt(long, parse(try_from_str = parse_bootnode))]
    pub additional_bootnode: Vec<Bootnode>,
    /// Bind point of the JSON-RPC server ("none" or <ip>:<port>).
    #[structopt(long, default_value = "127.0.0.1:9944", parse(try_from_str = parse_json_rpc_address))]
    pub json_rpc_address: JsonRpcAddress,
    /// List of secret phrases to insert in the keystore of the node. Used to author blocks.
    #[structopt(long, parse(try_from_str = decode_sr25519_private_key))]
    // TODO: also automatically add the same keys through ed25519?
    pub keystore_memory: Vec<[u8; 64]>,
    /// Address of a Jaeger agent to send traces to (hint: port is typically 6831).
    #[structopt(long)]
    pub jaeger: Option<SocketAddr>,
    /// Do not load or store anything on disk.
    #[structopt(long)]
    pub tmp: bool,
}

#[derive(Debug, clap::StructOpt)]
pub struct CliOptionsBlake264Hash {
    /// Payload whose hash to compute.
    pub payload: String,
}

#[derive(Debug)]
pub enum CliChain {
    Polkadot,
    Kusama,
    Westend,
    Custom(PathBuf),
}

impl core::str::FromStr for CliChain {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "polkadot" {
            Ok(CliChain::Polkadot)
        } else if s == "kusama" {
            Ok(CliChain::Kusama)
        } else if s == "westend" {
            Ok(CliChain::Westend)
        } else {
            Ok(CliChain::Custom(s.parse()?))
        }
    }
}

#[derive(Debug)]
pub enum ColorChoice {
    Always,
    Never,
}

impl core::str::FromStr for ColorChoice {
    type Err = ColorChoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "always" {
            Ok(ColorChoice::Always)
        } else if s == "auto" {
            if atty::is(atty::Stream::Stderr) {
                Ok(ColorChoice::Always)
            } else {
                Ok(ColorChoice::Never)
            }
        } else if s == "never" {
            Ok(ColorChoice::Never)
        } else {
            Err(ColorChoiceParseError)
        }
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display(fmt = "Color must be one of: always, auto, never")]
pub struct ColorChoiceParseError;

#[derive(Debug)]
pub enum Output {
    Auto,
    None,
    Informant,
    Logs,
    LogsJson,
}

impl core::str::FromStr for Output {
    type Err = OutputParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "auto" {
            Ok(Output::Auto)
        } else if s == "none" {
            Ok(Output::None)
        } else if s == "informant" {
            Ok(Output::Informant)
        } else if s == "logs" {
            Ok(Output::Logs)
        } else if s == "logs-json" {
            Ok(Output::LogsJson)
        } else {
            Err(OutputParseError)
        }
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display(fmt = "Output must be one of: auto, none, informant, logs, logs-json")]
pub struct OutputParseError;

#[derive(Debug)]
pub struct JsonRpcAddress(pub Option<SocketAddr>);

fn parse_json_rpc_address(string: &str) -> Result<JsonRpcAddress, String> {
    if string == "none" {
        return Ok(JsonRpcAddress(None));
    }

    if let Ok(addr) = string.parse::<SocketAddr>() {
        return Ok(JsonRpcAddress(Some(addr)));
    }

    Err("Failed to parse JSON-RPC server address".into())
}

#[derive(Debug)]
pub struct Bootnode {
    pub address: Multiaddr,
    pub peer_id: PeerId,
}

fn parse_bootnode(string: &str) -> Result<Bootnode, String> {
    let mut address = string.parse::<Multiaddr>().map_err(|err| err.to_string())?;
    if let Some(ProtocolRef::P2p(peer_id)) = address.iter().last() {
        let peer_id = PeerId::from_bytes(peer_id.to_vec())
            .map_err(|(err, _)| format!("Failed to parse PeerId in bootnode: {}", err))?;
        address.pop();
        Ok(Bootnode { address, peer_id })
    } else {
        Err("Bootnode address must end with /p2p/...".into())
    }
}

// `clap` requires error types to implement the `std::error::Error` trait.
// For this reason, we locally define some wrappers.
fn decode_ed25519_private_key(phrase: &str) -> Result<[u8; 32], String> {
    seed_phrase::decode_ed25519_private_key(phrase).map_err(|err| err.to_string())
}
fn decode_sr25519_private_key(phrase: &str) -> Result<[u8; 64], String> {
    seed_phrase::decode_sr25519_private_key(phrase).map_err(|err| err.to_string())
}
fn decode_multiaddr(addr: &str) -> Result<Multiaddr, String> {
    addr.parse::<Multiaddr>().map_err(|err| err.to_string())
}
