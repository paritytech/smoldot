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

//! Contains a light client implementation usable from a browser environment.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

use core::{
    cmp::Ordering,
    ops::{Add, Sub},
    slice, str,
    time::Duration,
};
use futures::{channel::mpsc, prelude::*};
use std::sync::Mutex;

pub mod bindings;

mod alloc;
mod init;
mod platform;
mod timers;

/// Uses the environment to invoke `closure` after at least `duration` has elapsed.
fn start_timer_wrap(duration: Duration, closure: impl FnOnce()) {
    let callback: Box<Box<dyn FnOnce()>> = Box::new(Box::new(closure));
    let timer_id = u32::try_from(Box::into_raw(callback) as usize).unwrap();
    // Note that ideally `duration` should be rounded up in order to make sure that it is not
    // truncated, but the precision of an `f64` is so high and the precision of the operating
    // system generally so low that this is not worth dealing with.
    unsafe { bindings::start_timer(timer_id, duration.as_secs_f64() * 1000.0) }
}

#[derive(Debug, Copy, Clone)]
pub struct Instant {
    /// Milliseconds.
    inner: f64,
}

impl PartialEq for Instant {
    fn eq(&self, other: &Instant) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Instant {}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Instant) -> Option<Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl Ord for Instant {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.partial_cmp(&other.inner).unwrap()
    }
}

impl Instant {
    pub fn now() -> Instant {
        Instant {
            inner: unsafe { bindings::monotonic_clock_ms() },
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        let new_val = self.inner + other.as_millis() as f64;
        Instant {
            inner: new_val as f64,
        }
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        let new_val = self.inner - other.as_millis() as f64;
        Instant {
            inner: new_val as f64,
        }
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        let ms = self.inner - other.inner;
        assert!(ms >= 0.0);
        Duration::from_millis(ms as u64)
    }
}

lazy_static::lazy_static! {
    static ref CLIENT: Mutex<Option<init::Client<Vec<future::AbortHandle>, platform::Platform>>> = Mutex::new(None);
}

fn init(max_log_level: u32) {
    let init_out = init::init(max_log_level);

    let mut client_lock = crate::CLIENT.lock().unwrap();
    assert!(client_lock.is_none());
    *client_lock = Some(init_out);
}

fn add_chain(
    chain_spec_pointer: u32,
    chain_spec_len: u32,
    database_content_pointer: u32,
    database_content_len: u32,
    json_rpc_running: u32,
    potential_relay_chains_ptr: u32,
    potential_relay_chains_len: u32,
) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();

    // Fail any new chain initialization if we're running low on memory space, which can
    // realistically happen as Wasm is a 32 bits platform. This avoids potentially running into
    // OOM errors. The threshold is completely empirical and should probably be updated
    // regularly to account for changes in the implementation.
    if alloc::total_alloc_bytes() >= usize::max_value() - 400 * 1024 * 1024 {
        let chain_id = client_lock.as_mut().unwrap().smoldot.add_erroneous_chain(
            "Wasm node is running low on memory and will prevent any new chain from being added"
                .into(),
            Vec::new(),
        );

        return chain_id.into();
    }

    // Retrieve the chain spec parameter passed through the FFI layer.
    let chain_spec: Box<[u8]> = {
        let chain_spec_pointer = usize::try_from(chain_spec_pointer).unwrap();
        let chain_spec_len = usize::try_from(chain_spec_len).unwrap();
        unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                chain_spec_pointer as *mut u8,
                chain_spec_len,
            ))
        }
    };

    // Retrieve the database content parameter passed through the FFI layer.
    let database_content: Box<[u8]> = {
        let database_content_pointer = usize::try_from(database_content_pointer).unwrap();
        let database_content_len = usize::try_from(database_content_len).unwrap();
        unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                database_content_pointer as *mut u8,
                database_content_len,
            ))
        }
    };

    // Retrieve the potential relay chains parameter passed through the FFI layer.
    let potential_relay_chains: Vec<_> = {
        let allowed_relay_chains_ptr = usize::try_from(potential_relay_chains_ptr).unwrap();
        let allowed_relay_chains_len = usize::try_from(potential_relay_chains_len).unwrap();

        let raw_data = unsafe {
            Box::from_raw(slice::from_raw_parts_mut(
                allowed_relay_chains_ptr as *mut u8,
                allowed_relay_chains_len * 4,
            ))
        };

        raw_data
            .chunks(4)
            .map(|c| u32::from_le_bytes(<[u8; 4]>::try_from(c).unwrap()))
            .map(smoldot_light_base::ChainId::from)
            .collect()
    };

    // If `json_rpc_running` is non-zero, then we pass a `Sender<String>` to the `add_client`
    // function. The client will push on this channel the JSON-RPC responses and notifications.
    //
    // After the client has pushed a response or notification, we must then propagate it to the
    // FFI layer. This is achieved by spawning a task that continuously polls the `Receiver` (see
    // below).
    //
    // When the chain is later removed, we want the task to immediately stop without sending any
    // additional response or notification to the FFI. This is achieved by storing an
    // `AbortHandle` as the "user data" of the chain within the client. When the chain is removed,
    // the client will yield back this `AbortHandle` and we can use it to abort the task.
    let (json_rpc_responses, responses_rx_and_reg, abort_handle) = if json_rpc_running != 0 {
        let (tx, rx) = mpsc::channel::<String>(64);
        let (handle, reg) = future::AbortHandle::new_pair();
        (Some(tx), Some((rx, reg)), Some(handle))
    } else {
        (None, None, None)
    };

    // Insert the chain in the client.
    let chain_id =
        client_lock
            .as_mut()
            .unwrap()
            .smoldot
            .add_chain(smoldot_light_base::AddChainConfig {
                user_data: abort_handle.into_iter().collect(),
                specification: str::from_utf8(&chain_spec).unwrap(),
                database_content: str::from_utf8(&database_content).unwrap(),
                json_rpc_responses,
                potential_relay_chains: potential_relay_chains.into_iter(),
            });

    // Spawn the task if necessary.
    // See explanations above.
    if let Some((mut responses_rx, abort_registration)) = responses_rx_and_reg {
        let messages_out_task = async move {
            while let Some(response) = responses_rx.next().await {
                emit_json_rpc_response(&response, chain_id);
            }
        };

        client_lock
            .as_mut()
            .unwrap()
            .new_tasks_spawner
            .unbounded_send((
                "json-rpc-messages-out".to_owned(),
                future::Abortable::new(messages_out_task, abort_registration)
                    .map(|_| ())
                    .boxed(),
            ))
            .unwrap();
    }

    chain_id.into()
}

fn remove_chain(chain_id: u32) {
    let mut client_lock = CLIENT.lock().unwrap();

    let abort_handles = client_lock
        .as_mut()
        .unwrap()
        .smoldot
        .remove_chain(smoldot_light_base::ChainId::from(chain_id));

    // Abort the tasks that retrieve the database content or poll the channel and send out the
    // JSON-RPC responses. This prevents any database callback from being called, and any new
    // JSON-RPC response concerning this chain from ever being sent back, even if some were still
    // pending.
    // Note that this only works because Wasm is single-threaded, otherwise the task being aborted
    // might be in the process of being polled.
    // TODO: solve this in case we use Wasm threads in the future
    for abort_handle in abort_handles {
        abort_handle.abort();
    }
}

fn chain_is_ok(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    if client_lock
        .as_mut()
        .unwrap()
        .smoldot
        .chain_is_erroneous(smoldot_light_base::ChainId::from(chain_id))
        .is_some()
    {
        0
    } else {
        1
    }
}

fn chain_error_len(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    let len = client_lock
        .as_mut()
        .unwrap()
        .smoldot
        .chain_is_erroneous(smoldot_light_base::ChainId::from(chain_id))
        .map(|msg| msg.as_bytes().len())
        .unwrap_or(0);
    u32::try_from(len).unwrap()
}

fn chain_error_ptr(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.lock().unwrap();
    let ptr = client_lock
        .as_mut()
        .unwrap()
        .smoldot
        .chain_is_erroneous(smoldot_light_base::ChainId::from(chain_id))
        .map(|msg| msg.as_bytes().as_ptr() as usize)
        .unwrap_or(0);
    u32::try_from(ptr).unwrap()
}

fn json_rpc_send(ptr: u32, len: u32, chain_id: u32) {
    let chain_id = smoldot_light_base::ChainId::from(chain_id);

    let json_rpc_request: Box<[u8]> = {
        let ptr = usize::try_from(ptr).unwrap();
        let len = usize::try_from(len).unwrap();
        unsafe { Box::from_raw(slice::from_raw_parts_mut(ptr as *mut u8, len)) }
    };

    // As mentioned in the documentation, the bytes *must* be valid UTF-8.
    let json_rpc_request: String = String::from_utf8(json_rpc_request.into()).unwrap();

    let mut client_lock = CLIENT.lock().unwrap();

    if let Err(err) = client_lock
        .as_mut()
        .unwrap()
        .smoldot
        .json_rpc_request(json_rpc_request, chain_id)
    {
        if let Some(response) = err.into_json_rpc_error() {
            emit_json_rpc_response(&response, chain_id);
        }
    }
}

fn database_content(chain_id: u32, max_size: u32) {
    let client_chain_id = smoldot_light_base::ChainId::from(chain_id);

    let mut client_lock = CLIENT.lock().unwrap();
    let init::Client {
        smoldot: client,
        new_tasks_spawner,
    } = client_lock.as_mut().unwrap();

    let task = {
        let max_size = usize::try_from(max_size).unwrap();
        let future = client.database_content(client_chain_id, max_size);
        async move {
            let content = future.await;
            unsafe {
                bindings::database_content_ready(
                    u32::try_from(content.as_ptr() as usize).unwrap(),
                    u32::try_from(content.len()).unwrap(),
                    chain_id,
                );
            }
        }
    };

    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
    client
        .chain_user_data_mut(client_chain_id)
        .push(abort_handle);

    new_tasks_spawner
        .unbounded_send((
            "database_content-output".to_owned(),
            future::Abortable::new(task, abort_registration)
                .map(|_| ())
                .boxed(),
        ))
        .unwrap();
}

fn emit_json_rpc_response(rpc: &str, chain_id: smoldot_light_base::ChainId) {
    unsafe {
        bindings::json_rpc_respond(
            u32::try_from(rpc.as_bytes().as_ptr() as usize).unwrap(),
            u32::try_from(rpc.as_bytes().len()).unwrap(),
            u32::from(chain_id),
        );
    }
}
