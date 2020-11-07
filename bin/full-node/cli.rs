// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

use std::{net::SocketAddr, path::PathBuf};

/// Information about the binary for the `app_dirs` library.
pub const APP_INFO: app_dirs::AppInfo = app_dirs::AppInfo {
    name: "substrate-lite",
    author: "paritytech",
};

// Note: the doc-comments applied to this struct and its field are visible when the binary is
// started with `--help`.

#[derive(Debug, structopt::StructOpt)]
pub struct CliOptions {
    /// Chain to connect to ("polkadot", "kusama", "westend", or a file path).
    #[structopt(long, default_value = "polkadot")]
    pub chain: CliChain,
    /// Output to stdout: auto, none, informant, logs, logs-json.
    #[structopt(long, default_value = "auto")]
    pub output: Output,
    /// Coloring: auto, always, never
    #[structopt(long, default_value = "auto")]
    pub color: ColorChoice,
    /// Address of a Jaeger server to send traces to (help: port is typically 6831).
    #[structopt(long)]
    pub jaeger: Option<SocketAddr>,
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
            if atty::is(atty::Stream::Stdout) {
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
    None,
    Informant,
    Logs,
    LogsJson,
}

impl core::str::FromStr for Output {
    type Err = OutputParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "auto" {
            if atty::is(atty::Stream::Stdout) {
                Ok(Output::Informant)
            } else {
                Ok(Output::Logs)
            }
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
