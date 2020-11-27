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

//! Jaeger integration.
//!
//! See <https://www.jaegertracing.io/> for an introduction.
//!
//! The easiest way to try Jaeger is:
//!
//! - Start a docker container with the all-in-one docker image (see below).
//! - Run [`JaegerService`] with [`Config::jaeger_agent`] set to `127.0.0.1:6831`.
//! - Open your browser and navigate to <https://localhost:16686> to acces the UI.
//!
//! The all-in-one docker image can be started with:
//!
//! ```not_rust
//! docker run -d --name jaeger \
//!  -e COLLECTOR_ZIPKIN_HTTP_PORT=9411 \
//!  -p 5775:5775/udp \
//!  -p 6831:6831/udp \
//!  -p 6832:6832/udp \
//!  -p 5778:5778 \
//!  -p 16686:16686 \
//!  -p 14268:14268 \
//!  -p 14250:14250 \
//!  -p 9411:9411 \
//!  jaegertracing/all-in-one:1.21
//! ```
//!

// TODO: more documentation

use async_std::net::UdpSocket;
use substrate_lite::network::PeerId;
use std::{
    convert::TryFrom as _, future::Future, io, net::SocketAddr, num::NonZeroU128, pin::Pin,
    sync::Arc,
};

/// Configuration for a [`JaegerService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Service name to report to the Jaeger agent.
    pub service_name: String,

    /// Address of the Jaeger agent to send traces to.
    pub jaeger_agent: Option<SocketAddr>,
}

pub struct JaegerService {
    traces_in: Arc<mick_jaeger::TracesIn>,
}

impl JaegerService {
    pub async fn new(mut config: Config) -> Result<Arc<Self>, io::Error> {
        let (traces_in, mut traces_out) = mick_jaeger::init(mick_jaeger::Config {
            service_name: config.service_name,
        });

        if let Some(jaeger_agent) = config.jaeger_agent {
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

            // Spawn a background task that pulls span information and sends them on the network.
            (config.tasks_executor)(Box::pin(async move {
                loop {
                    let buf = traces_out.next().await;
                    // UDP sending errors happen only either if the API is misused (in which case
                    // panicking is desirable) or in case of missing priviledge, in which case a
                    // panic is preferable in order to inform the user.
                    udp_socket.send_to(&buf, jaeger_agent).await.unwrap();
                }
            }));
        }

        Ok(Arc::new(JaegerService { traces_in }))
    }

    // TODO: consider removing
    pub fn background_task_span(&self, task_name: impl Into<String>) -> mick_jaeger::Span {
        // TODO: don't put it random?
        self.traces_in.span(rand::random(), task_name)
    }

    pub fn block_span(
        &self,
        block_hash: &[u8; 32],
        operation_name: impl Into<String>,
    ) -> mick_jaeger::Span {
        let trace_id = NonZeroU128::new(u128::from_be_bytes(
            <[u8; 16]>::try_from(&block_hash[16..]).unwrap(),
        ))
        .unwrap_or(NonZeroU128::new(1u128).unwrap());
        self.traces_in.span(trace_id, operation_name)
    }

    /// Creates a new `Span` that refers to a specific network connection between two nodes.
    pub fn net_connection_span(
        &self,
        local_peer_id: &PeerId,
        remote_peer_id: &PeerId,
        operation_name: impl Into<String>,
    ) -> mick_jaeger::Span {
        let local_peer_id = local_peer_id.as_bytes();
        let remote_peer_id = remote_peer_id.as_bytes();

        let mut buf = [0; 16];
        if local_peer_id < remote_peer_id {
            buf[..8].copy_from_slice(&local_peer_id[local_peer_id.len() - 8..]);
            buf[8..].copy_from_slice(&remote_peer_id[remote_peer_id.len() - 8..]);
        } else {
            buf[..8].copy_from_slice(&remote_peer_id[remote_peer_id.len() - 8..]);
            buf[8..].copy_from_slice(&local_peer_id[local_peer_id.len() - 8..]);
        };

        let trace_id = NonZeroU128::new(u128::from_be_bytes(buf)).unwrap();
        self.traces_in.span(trace_id, operation_name)
    }
}
