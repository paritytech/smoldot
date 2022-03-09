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
#![deny(unused_crate_dependencies)]

use clap::Parser;
use webrtc::api::APIBuilder;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::certificate::RTCCertificate;
use futures as _;
use anyhow::Result;
use async_std::fs;
use async_std::sync::Arc;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Listen address to bind to
    #[clap(short, long, default_value = "localhost:19302")]
    listen_addr: String,
}

#[async_std::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let api = APIBuilder::new().build();
    let certificate = load_certificate().await.expect("failed to load certificate");
    let config = RTCConfiguration {
        certificates: vec![certificate],
        ..Default::default()
    };

    let peer_connection = Arc::new(api.new_peer_connection(config).await?);

    Ok(())
}

async fn load_certificate() -> Result<RTCCertificate> {
    let pk = fs::read_to_string("./static/privateKey.key").await?;
    let cert = fs::read_to_string("./static/certificate.crt").await?;

    Ok(RTCCertificate::from_pem(&cert, rcgen::KeyPair::from_pem(&pk)?)?)
}
