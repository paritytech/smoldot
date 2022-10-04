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

#![recursion_limit = "1024"]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

mod cli;
mod run;

fn main() {
    futures::executor::block_on(async_main())
}

async fn async_main() {
    match <cli::CliOptions as clap::Parser>::parse() {
        cli::CliOptions::Run(r) => run::run(*r).await,
        cli::CliOptions::Blake264BitsHash(opt) => {
            let hash = blake2_rfc::blake2b::blake2b(8, &[], opt.payload.as_bytes());
            println!("0x{}", hex::encode(hash));
        }
    }
}
