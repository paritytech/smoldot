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

//! Provides the [`CliOptions`] struct that contains all the CLI options that can be passed to the
//! binary.
//!
//! See the documentation of the [`structopt`] crate in order to learn more.
//!
//! # Example
//!
//! ```no_run
//! use structopt::StructOpt as _;
//! let cli_options = full_node::CliOptions::from_args();
//! println!("Quiet: {:?}", cli_options.quiet);
//! ```
//!
// TODO: I believe this example isn't tested ^ which kills the point of having it

use smoldot::ss58;
use std::{net::SocketAddr, path::PathBuf};

// Note: the doc-comments applied to this struct and its field are visible when the binary is
// started with `--help`.

#[derive(Debug, structopt::StructOpt)]
pub enum CliOptions {
    /// Connect to the chain and synchronize the local database with the network.
    Run(CliOptionsRun),
}

#[derive(Debug, structopt::StructOpt)]
pub struct CliOptionsRun {
    /// Chain to connect to ("polkadot", "kusama", "westend", or a file path).
    #[structopt(long, default_value = "polkadot")]
    pub chain: CliChain,
    /// Output to stdout: auto, none, informant, logs, logs-json.
    #[structopt(long, default_value = "auto")]
    pub output: Output,
    /// Log filter. Example: foo=trace
    #[structopt(long)]
    pub log: Vec<tracing_subscriber::filter::Directive>,
    /// Coloring: auto, always, never
    #[structopt(long, default_value = "auto")]
    pub color: ColorChoice,
    /// Ed25519 private key of network identity (32 bytes hexadecimal).
    #[structopt(long)]
    pub libp2p_key: Option<Libp2pKey>,
    /// Bind point of the JSON-RPC server ("none" or <ip>:<port>).
    #[structopt(long, default_value = "127.0.0.1:9944", parse(try_from_str = parse_json_rpc_address))]
    pub json_rpc_address: JsonRpcAddress,
    /// List of secret phrases to insert in the keystore of the node. Used to author blocks.
    #[structopt(long, parse(try_from_str = ss58::decode_private_key))]
    pub keystore_memory: Vec<[u8; 64]>,
    /// Do not load or store anything on disk.
    #[structopt(long)]
    pub tmp: bool,
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

#[derive(Debug, derive_more::Display)]
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

#[derive(Debug, derive_more::Display)]
#[display(fmt = "Output must be one of: auto, none, informant, logs, logs-json")]
pub struct OutputParseError;

// Note: while it is tempting to zero-ize the content of `NodeKey` on Drop, since the node key is
// passed through the CLI, it is going to be present at several other locations in memory, plus on
// the system. Any zero-ing here would be completely superfluous.
#[derive(Debug)]
pub struct Libp2pKey([u8; 32]);

impl core::str::FromStr for Libp2pKey {
    type Err = NodeKeyParseError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("0x") {
            s = &s[2..];
        }

        if s.len() != 64 {
            return Err(NodeKeyParseError::BadLength);
        }

        let bytes = hex::decode(s).map_err(NodeKeyParseError::FromHex)?;

        let mut out = [0; 32];
        out.copy_from_slice(&bytes);

        ed25519_zebra::SigningKey::try_from(out).map_err(|_| NodeKeyParseError::BadKey)?;

        Ok(Libp2pKey(out))
    }
}

impl AsRef<[u8; 32]> for Libp2pKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, derive_more::Display)]
pub enum NodeKeyParseError {
    #[display(fmt = "Expected 64 hexadecimal digits")]
    BadLength,
    #[display(fmt = "{}", _0)]
    FromHex(hex::FromHexError),
    #[display(fmt = "Invalid ed25519 private key")]
    BadKey,
}

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
