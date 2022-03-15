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


use std::time::Duration;

use clap::Parser;
use webrtc::api::APIBuilder;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::peer_connection::certificate::RTCCertificate;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::math_rand_alpha;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc_ice::udp_network::UDPNetwork;
use webrtc_ice::udp_mux::UDPMuxParams;
use webrtc_ice::udp_mux::UDPMuxDefault;
use futures::{channel::oneshot, prelude::*};
use anyhow::Result;
use async_std::fs;
use async_std::sync::Arc;
use async_std::task;
use async_std::channel as async_channel;
// webrtc_util::conn::Conn is not implemented for UdpSocket
// use async_std::net::UdpSocket;
use tokio::net::UdpSocket;

/// An SDP message that constitutes the offer.
/// Main RFC: <https://datatracker.ietf.org/doc/html/rfc8866>
/// `sctp-port` and `max-message-size` attrs RFC: <https://datatracker.ietf.org/doc/html/rfc8841>
/// `group` and `mid` attrs RFC: <https://datatracker.ietf.org/doc/html/rfc9143>
/// `ice-ufrag`, `ice-pwd` and `ice-options` attrs RFC: <https://datatracker.ietf.org/doc/html/rfc8839>
/// `setup` attr RFC: <https://datatracker.ietf.org/doc/html/rfc8122>
///
/// Short description:
///     v=<protocol-version>
///     o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
///     s=<session name>
///     c=<nettype> <addrtype> <connection-address>
///     t=<start-time> <stop-time>
///     a=group:BUNDLE <name>, ...
///
///     m=<media> <port> <proto> <fmt> ...
///     a=mid:<MID>
///     a=ice-options:ice2
///     a=ice-ufrag:<ICE user>
///     a=ice-pwd:<ICE password>
///     a=setup:<setup>
///     a=sctp-port:<value>
///     a=max-message-size:<value>
const CLIENT_SESSION_DESCRIPTION: &'static str = "v=0
o=- 0 0 IN IP4 0.0.0.0
s=-
c=IN IP4 0.0.0.0
t=0 0
a=group:BUNDLE 0

m=application 9 UDP/DTLS/SCTP webrtc-datachannel
a=mid:0
a=ice-options:ice2
a=ice-ufrag:V6j+
a=ice-pwd:OEKutPgoHVk/99FfqPOf444w
a=fingerprint:sha-256 invalidFingerprint
a=setup:actpass
a=sctp-port:5000
a=max-message-size:100000
";

const ICE_USER: &str = "aIGX";
const ICE_PASSWD: &str = "ndajecaXt6vPIt6VYcUL8wpW";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Listen address to bind to
    #[clap(short, long, default_value = "127.0.0.1:41000")]
    listen_addr: String,
}

#[async_std::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // TODO: async_std UdpSocket
    let socket = UdpSocket::bind(cli.listen_addr).await?;

    // Starting from here, a SIGINT (or equivalent) handler is setup. If the user does Ctrl+C,
    // a message will be sent on `ctrlc_rx`.
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

    let mut se = SettingEngine::default();
    se.disable_certificate_fingerprint_verification(true);
    se.set_udp_network(UDPNetwork::Muxed(UDPMuxDefault::new(UDPMuxParams::new(socket))));
    se.set_ice_credentials(ICE_USER.to_string(), ICE_PASSWD.to_string());
    let api = APIBuilder::new().with_setting_engine(se).build();
    let certificate = load_certificate().await.expect("failed to load certificate");
    let config = RTCConfiguration {
        certificates: vec![certificate],
        ..Default::default()
    };

    let peer_connection = Arc::new(api.new_peer_connection(config).await?);

    let (done_tx, done_rx) = async_channel::bounded(1);
    
    peer_connection
        .on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            println!("Peer Connection State has changed: {}", s);

            if s == RTCPeerConnectionState::Failed {
                // Wait until PeerConnection has had no network activity for 30 seconds or another
                // failure. It may be reconnected using an ICE Restart. Use
                // webrtc.PeerConnectionStateDisconnected if you are interested in detecting faster
                // timeout. Note that the PeerConnection may come back from
                // PeerConnectionStateDisconnected.
                println!("Peer Connection has gone to failed exiting");
                let _ = done_tx.try_send(());
            }

            Box::pin(async {})
        }))
        .await;
    
    peer_connection
        .on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
            let d_label = d.label().to_owned();
            let d_id = d.id();
            println!("New DataChannel {} {}", d_label, d_id);

            // Register channel opening handling
            Box::pin(async move {
                let d2 = Arc::clone(&d);
                let d_label2 = d_label.clone();
                let d_id2 = d_id;
                d.on_open(Box::new(move || {
                    println!("Data channel '{}'-'{}' open. Random messages will now be sent to any connected DataChannels every 5 seconds", d_label2, d_id2);

                    Box::pin(async move {
                        let mut result = Result::<usize>::Ok(0);
                        while result.is_ok() {
                            task::sleep(Duration::from_secs(5)).await;

                            let message = math_rand_alpha(15);
                            println!("Sending '{}'", message);
                            result = d2.send_text(message).await.map_err(Into::into);
                        }
                    })
                })).await;

                // Register text message handling
                d.on_message(Box::new(move |msg: DataChannelMessage| {
                    let msg_str = String::from_utf8(msg.data.to_vec()).unwrap();
                    println!("Message from DataChannel '{}': '{}'", d_label, msg_str);
                    Box::pin(async {})
                })).await;
            })
        }))
        .await;
    
    // Set the remote description to the predefined SDP
    let mut offer = peer_connection.create_offer(None).await?;
    offer.sdp = CLIENT_SESSION_DESCRIPTION.to_string();
    peer_connection.set_remote_description(offer).await?;

    let answer = peer_connection.create_answer(None).await?;
    // Set the local description and start UDP listeners
    // Note: this will start the gathering of ICE candidates
    peer_connection.set_local_description(answer).await?;

    futures::select! {
        _ = done_rx.recv().fuse() => {
            println!("received done signal!");
        }
        _ = ctrlc_rx => {
            println!("received interrupt signal!");
        },
    }

    peer_connection.close().await?;

    Ok(())
}

async fn load_certificate() -> Result<RTCCertificate> {
    let pk = fs::read_to_string("./static/privateKey.key").await?;
    let cert = fs::read_to_string("./static/certificate.crt").await?;

    Ok(RTCCertificate::from_pem(&cert, rcgen::KeyPair::from_pem(&pk)?)?)
}
