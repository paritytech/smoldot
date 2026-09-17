// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::{AddChainConfig, AddChainConfigJsonRpc, Client, platform};
use core::{
    future::Future,
    ops::{Deref, DerefMut},
};
use serde_json::{Value, json};
use smoldot::{
    jam::{
        crypto::blake2b_256,
        types::{Hash, SealingSequence},
    },
    libp2p::read_write::ReadWrite,
};
use std::{collections::BTreeMap, sync::Mutex, time::Instant};

fn root_state() -> State {
    let mut params = Params::from_protocol_parameters(&{
        let mut bytes = [0; 122];
        bytes[24] = 2;
        bytes
    })
    .unwrap();
    params.epoch_len = 1;
    params.max_validators = 6;
    params.slot_seconds = 6;
    let header = Header {
        parent: [0; 32],
        prior_state_root: [0; 32],
        extrinsic_hash: [0; 32],
        slot: 0,
        epoch_mark: None,
        tickets_mark: None,
        author_index: 0,
        entropy_source: [0; 96],
        offenders_mark: Vec::new(),
        seal: [0; 96],
    };
    let state = LightState {
        entropy: [[0; 32]; 4],
        active: vec![([0; 32], [0; 32]); 6],
        pending: vec![([0; 32], [0; 32]); 6],
        sealing: SealingSequence::Keys(vec![[0; 32]]),
        pending_tickets: None,
        slot: 0,
    };
    State {
        tree: HeaderTree::new(
            params.clone(),
            verified_genesis(&params, header, state),
            tree::Config {
                max_blocks: NonZeroUsize::new(4).unwrap(),
            },
        ),

        params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: 4096,
    }
}

#[test]
fn snapshot_excludes_root_and_refuses_runtime_and_excess_subscribers() {
    let mut state = root_state();
    let snapshot = state.subscribe(0, false);
    assert!(snapshot.non_finalized_blocks_ancestry_order.is_empty());
    assert_eq!(
        blake2b_256(&snapshot.finalized_block_scale_encoded_header),
        state.tree.finalized().hash
    );
    assert!(snapshot.finalized_block_runtime.is_none());
    assert_eq!(snapshot.new_blocks.capacity(), Some(1));
    assert!(state.subscribe(usize::MAX, true).new_blocks.is_closed());
    let mut retained = vec![snapshot];
    for _ in 1..MAX_SUBSCRIBERS {
        retained.push(state.subscribe(usize::MAX, false));
    }
    assert!(state.subscribe(1, false).new_blocks.is_closed());
    state.stopped = true;
    assert!(state.subscribe(1, false).new_blocks.is_closed());
}

#[test]
fn invalid_header_does_not_change_anchor_or_notify() {
    let mut state = root_state();
    let snapshot = state.subscribe(1, false);
    let root = state.tree.finalized().clone();
    let mut child = root.header.clone();
    child.parent = root.hash;
    child.slot = 1;
    assert!(state.insert(child, u64::MAX).is_err());
    assert_eq!(state.tree.len(), 1);
    assert_eq!(state.tree.finalized(), &root);
    assert!(snapshot.new_blocks.try_recv().is_err());
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
struct FakePlatform(Arc<Mutex<Control>>);
struct Control {
    handshake: Vec<u8>,
    responses: BTreeMap<Hash, Vec<u8>>,
    requests: Vec<BlockRequest>,
    attempts: usize,
    fail_first: bool,
    supported: bool,
    pins: Vec<Vec<[u8; 32]>>,
    disconnect: bool,
    starve: bool,
    queued: bool,
    clock_shift: Duration,
    io: IoState,
}

#[derive(Default)]
struct IoState {
    params: Option<Params>,
    reject_batch_above: Option<u32>,
    preferred_child: Option<(Hash, Hash)>,
    no_blocks: usize,
    fork_announcement: Option<Vec<u8>>,
    event_driven: bool,
    changed: Arc<event_listener::Event>,
    executor: Option<Arc<smol::Executor<'static>>>,
    pending_waits: usize,
    live_connections: usize,
    live_streams: usize,
    live_tasks: usize,
    tasks_spawned: usize,
    stall_outbound: bool,
    stalled_openings: usize,
}
struct FakeConnection {
    control: Arc<Mutex<Control>>,
    streams: VecDeque<FakeStream>,
    number: usize,
    dead: bool,
}
struct FakeStream {
    control: Arc<Mutex<Control>>,
    rw: ReadWrite<Instant>,
    incoming: VecDeque<u8>,
    outgoing: Vec<u8>,
    ce: bool,
    response_started: bool,
    inbound: bool,
}

impl Drop for FakeConnection {
    fn drop(&mut self) {
        self.control.lock().unwrap().io.live_connections -= 1;
    }
}

impl Drop for FakeStream {
    fn drop(&mut self) {
        self.control.lock().unwrap().io.live_streams -= 1;
    }
}

struct TaskGuard(Arc<Mutex<Control>>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.lock().unwrap().io.live_tasks -= 1;
    }
}
struct Access<'a>(&'a mut ReadWrite<Instant>);
impl Deref for Access<'_> {
    type Target = ReadWrite<Instant>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
impl DerefMut for Access<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl PlatformRef for FakePlatform {
    type Delay = BoxFuture<'static, ()>;
    type Instant = Instant;
    type MultiStream = FakeConnection;
    type Stream = FakeStream;
    type ReadWriteAccess<'a> = Access<'a>;
    type StreamErrorRef<'a> = &'a str;
    type StreamConnectFuture = BoxFuture<'static, FakeStream>;
    type MultiStreamConnectFuture =
        BoxFuture<'static, platform::MultiStreamWebRtcConnection<FakeConnection>>;
    type StreamUpdateFuture<'a> = BoxFuture<'a, ()>;
    type NextSubstreamFuture<'a> = BoxFuture<'a, Option<(FakeStream, SubstreamDirection)>>;
    fn now_from_unix_epoch(&self) -> Duration {
        Duration::from_secs(1_800_000_000)
    }
    fn now(&self) -> Instant {
        Instant::now() + self.0.lock().unwrap().clock_shift
    }
    fn fill_random_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(7);
    }
    fn sleep(&self, duration: Duration) -> Self::Delay {
        // Readiness regressions must not make progress via the driver's watchdog
        // polling. Other tests retain real timers for deadline/backoff coverage.
        if self.0.lock().unwrap().io.event_driven && duration == Duration::from_millis(100) {
            return Box::pin(future::pending());
        }
        Box::pin(async move {
            smol::Timer::after(duration).await;
        })
    }
    fn sleep_until(&self, when: Instant) -> Self::Delay {
        Box::pin(async move {
            smol::Timer::at(when).await;
        })
    }
    fn spawn_task(&self, _: Cow<str>, task: impl Future<Output = ()> + Send + 'static) {
        let executor = {
            let mut c = self.0.lock().unwrap();
            c.io.live_tasks += 1;
            c.io.tasks_spawned += 1;
            c.io.executor.clone()
        };
        let guard = TaskGuard(self.0.clone());
        let task = async move {
            let _guard = guard;
            task.await;
        };
        if let Some(executor) = executor {
            executor.spawn(task).detach();
        } else {
            smol::spawn(task).detach();
        }
    }
    fn log<'a>(
        &self,
        _: platform::LogLevel,
        _: &'a str,
        message: &'a str,
        _: impl Iterator<Item = (&'a str, &'a dyn core::fmt::Display)>,
    ) {
        if message == "jam-block-request-queued" {
            self.0.lock().unwrap().queued = true;
        }
    }
    fn client_name(&self) -> Cow<'_, str> {
        "fake".into()
    }
    fn client_version(&self) -> Cow<'_, str> {
        "1".into()
    }
    fn supports_connection_type(&self, ty: platform::ConnectionType) -> bool {
        self.0.lock().unwrap().supported && matches!(ty, platform::ConnectionType::WebTransportIpv4)
    }
    fn connect_stream(&self, _: platform::Address) -> Self::StreamConnectFuture {
        panic!("Substrate transport used for JAM")
    }
    fn connect_multistream(&self, address: MultiStreamAddress) -> Self::MultiStreamConnectFuture {
        assert!(self.supports_connection_type((&address).into()));
        let MultiStreamAddress::WebTransport { cert_hashes, .. } = address else {
            panic!("not WebTransport")
        };
        let mut c = self.0.lock().unwrap();
        c.attempts += 1;
        c.io.live_connections += 1;
        c.pins.push(cert_hashes.into_owned());
        let dead = c.fail_first && c.attempts == 1;
        let connection = FakeConnection {
            control: self.0.clone(),
            streams: VecDeque::new(),
            number: 0,
            dead,
        };
        Box::pin(async {
            platform::MultiStreamWebRtcConnection {
                connection,
                local_tls_certificate_sha256: [0; 32],
            }
        })
    }
    fn open_out_substream(&self, connection: &mut FakeConnection) {
        let ce = connection.number != 0;
        connection.number += 1;
        {
            let mut c = connection.control.lock().unwrap();
            if ce && c.io.stall_outbound {
                c.io.stalled_openings += 1;
                return;
            }
        }
        connection.control.lock().unwrap().io.live_streams += 1;
        let incoming = if ce {
            VecDeque::new()
        } else {
            connection.control.lock().unwrap().handshake.clone().into()
        };
        connection.streams.push_back(FakeStream {
            control: connection.control.clone(),
            rw: ReadWrite {
                now: Instant::now(),
                incoming_buffer: Vec::new(),
                expected_incoming_bytes: Some(1),
                read_bytes: 0,
                write_buffers: Vec::new(),
                write_bytes_queued: 0,
                write_bytes_queueable: Some(7),
                wake_up_after: None,
            },
            incoming,
            outgoing: Vec::new(),
            ce,
            response_started: false,
            inbound: false,
        });
        if !ce && connection.control.lock().unwrap().starve {
            connection.control.lock().unwrap().io.live_streams += 2;
            for _ in 0..2 {
                connection.streams.push_back(FakeStream {
                    control: connection.control.clone(),
                    rw: ReadWrite {
                        now: self.now(),
                        incoming_buffer: Vec::new(),
                        expected_incoming_bytes: Some(1),
                        read_bytes: 0,
                        write_buffers: Vec::new(),
                        write_bytes_queued: 0,
                        write_bytes_queueable: Some(7),
                        wake_up_after: None,
                    },
                    incoming: VecDeque::new(),
                    outgoing: Vec::new(),
                    ce: false,
                    response_started: false,
                    inbound: true,
                });
            }
        }
    }
    fn next_substream<'a>(
        &self,
        connection: &'a mut FakeConnection,
    ) -> Self::NextSubstreamFuture<'a> {
        Box::pin(async move {
            let (event_driven, changed) = {
                let c = connection.control.lock().unwrap();
                (c.io.event_driven, c.io.changed.clone())
            };
            loop {
                let listener = changed.listen();
                {
                    let mut c = connection.control.lock().unwrap();
                    if c.disconnect {
                        c.disconnect = false;
                        return None;
                    }
                }
                if connection.dead {
                    return None;
                }
                if let Some(stream) = connection.streams.pop_front() {
                    let direction = if stream.inbound {
                        SubstreamDirection::Inbound
                    } else {
                        SubstreamDirection::Outbound
                    };
                    return Some((stream, direction));
                }
                if event_driven {
                    listener.await;
                } else {
                    future::pending::<()>().await;
                }
            }
        })
    }
    fn read_write_access<'a>(
        &self,
        stream: Pin<&'a mut FakeStream>,
    ) -> Result<Access<'a>, &'a str> {
        let stream = stream.get_mut();
        for buffer in stream.rw.write_buffers.drain(..) {
            stream.outgoing.extend(buffer);
        }
        stream.rw.write_bytes_queued = 0;
        if stream.rw.write_bytes_queueable.is_some() {
            stream.rw.write_bytes_queueable = Some(7);
        }
        if stream.ce && !stream.response_started && stream.rw.write_bytes_queueable.is_none() {
            assert_eq!(stream.outgoing[0], 128);
            let request = BlockRequest::decode(&stream.outgoing[5..]).unwrap();
            assert!((1..=64).contains(&request.max_blocks));
            let mut control = stream.control.lock().unwrap();
            let mut payload = Vec::new();
            let mut hash = request.hash;
            for _ in 0..request.max_blocks.min(64) {
                let response = match request.direction {
                    Direction::DescendingInclusive => control.responses.get_key_value(&hash),
                    Direction::AscendingExclusive
                        if control
                            .io
                            .preferred_child
                            .is_some_and(|(parent, _)| parent == hash) =>
                    {
                        let (_, child) = control.io.preferred_child.unwrap();
                        control.responses.get_key_value(&child)
                    }
                    Direction::AscendingExclusive => control
                        .responses
                        .iter()
                        .find(|(_, frame)| frame.get(4..36) == Some(hash.as_slice())),
                };
                let Some((next_hash, frame)) = response else {
                    break;
                };
                payload.extend_from_slice(&frame[4..]);
                // Legacy scripted responses retained headers only. Supply an
                // explicit empty extrinsic when serving those through CE128.
                if control
                    .io
                    .params
                    .as_ref()
                    .is_some_and(|params| Header::decode(params, &frame[4..]).is_ok())
                {
                    payload.extend([0; 7]);
                }
                hash = match request.direction {
                    Direction::AscendingExclusive => *next_hash,
                    Direction::DescendingInclusive => frame[4..36].try_into().unwrap(),
                };
            }
            let oversize = control
                .io
                .reject_batch_above
                .is_some_and(|limit| request.max_blocks > limit);
            control.requests.push(request);
            if payload.is_empty() {
                control.io.no_blocks += 1;
                return Err("no block");
            }
            stream.incoming = if oversize {
                u32::try_from(FRAME_BYTES + 1)
                    .unwrap()
                    .to_le_bytes()
                    .to_vec()
                    .into()
            } else {
                framed(payload).into()
            };
            stream.response_started = true;
        }
        if !stream.ce {
            let mut c = stream.control.lock().unwrap();
            if c.io.no_blocks >= 2
                && let Some(frame) = c.io.fork_announcement.take()
            {
                stream.incoming.extend(frame);
            }
        }
        let chunk = if stream.control.lock().unwrap().io.event_driven {
            stream.incoming.len()
        } else {
            17
        };
        for _ in 0..chunk {
            if let Some(byte) = stream.incoming.pop_front() {
                stream.rw.incoming_buffer.push(byte);
            }
        }
        if stream.ce && stream.response_started && stream.incoming.is_empty() {
            stream.rw.expected_incoming_bytes = None;
        }
        Ok(Access(&mut stream.rw))
    }
    fn wait_read_write_again<'a>(
        &self,
        stream: Pin<&'a mut FakeStream>,
    ) -> Self::StreamUpdateFuture<'a> {
        let (event_driven, changed) = {
            let c = self.0.lock().unwrap();
            (c.io.event_driven, c.io.changed.clone())
        };
        if !event_driven {
            return self.sleep(Duration::from_millis(1));
        }
        Box::pin(async move {
            let listener = changed.listen();
            let stream = stream.get_mut();
            // Already-buffered bytes do not generate a fresh platform readiness
            // edge. Only new input or transport-side output/response work does.
            if !stream.incoming.is_empty()
                || !stream.rw.write_buffers.is_empty()
                || (stream.ce
                    && !stream.response_started
                    && stream.rw.write_bytes_queueable.is_none())
            {
                return;
            }
            stream.control.lock().unwrap().io.pending_waits += 1;
            listener.await;
        })
    }
}

fn fixture(name: &str) -> Value {
    let root = std::env::var_os("JAM_A5_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into());
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn fixture_setup() -> (FakePlatform, String, Hash, Vec<u8>) {
    let mut spec = fixture("chain-spec.polkajam.json");
    let cert = fixture("cert_vector.json");
    let identity = cert[0]["p256_id_text"].as_str().unwrap();
    spec["bootnodes"] = json!([alloc::format!(
        "e{}+{identity}@127.0.0.1:4433",
        "a".repeat(52)
    )]);
    let up = fixture("messages/up0.json");
    let ce = fixture("messages/ce128.json");
    let mut handshake = bytes(&up["handshake_frame_hex"]);
    handshake.extend(bytes(&up["announcement_frame_hex"]));
    let request = BlockRequest::decode(&bytes(&ce["request_frame_hex"])[4..]).unwrap();
    let response = bytes(&ce["response_frame_hex"]);
    let encoded = bytes(&fixture("headers/0000.json")["header_hex"]);
    let platform = FakePlatform(Arc::new(Mutex::new(Control {
        handshake,
        responses: [(request.hash, response)].into(),
        requests: Vec::new(),
        attempts: 0,
        fail_first: false,
        supported: true,
        pins: Vec::new(),
        disconnect: false,
        starve: false,
        queued: false,
        clock_shift: Duration::ZERO,
        io: IoState::default(),
    })));
    platform.0.lock().unwrap().io.params = Some(
        JamChainSpec::from_json_bytes(spec.to_string().as_bytes())
            .unwrap()
            .params()
            .clone(),
    );
    (platform, spec.to_string(), request.hash, encoded)
}

async fn response(responses: &mut crate::JsonRpcResponses<FakePlatform>) -> Value {
    let text = future::or(
        async { responses.next().await.expect("RPC ended") },
        async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("RPC timed out")
        },
    )
    .await;
    serde_json::from_str(&text).unwrap()
}

#[test]
#[ignore = "requires external A5 fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_frames_add_chain_follow_header_unpin_unfollow_and_reconnect() {
    smol::block_on(async {
        let (platform, spec, hash, header) = fixture_setup();
        platform.0.lock().unwrap().fail_first = true;
        let mut client = Client::new(platform.clone());
        let added = client
            .add_chain(AddChainConfig {
                specification: &spec,
                user_data: (),
                database_content: "",
                potential_relay_chains: core::iter::empty(),
                json_rpc: AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
                    max_subscriptions: 2,
                },
                statement_protocol_config: None,
            })
            .unwrap();
        let mut responses = added.json_rpc_responses.unwrap();
        client
            .json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[false]}"#,
                added.chain_id,
            )
            .unwrap();
        let id = response(&mut responses).await["result"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            response(&mut responses).await["params"]["result"]["event"],
            "initialized"
        );
        let initial_best = response(&mut responses).await;
        assert_eq!(
            initial_best["params"]["result"]["event"],
            "bestBlockChanged"
        );
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        assert_eq!(
            initial_best["params"]["result"]["bestBlockHash"],
            alloc::format!(
                "0x{}",
                hex::encode(parsed.genesis_header().hash(parsed.params()))
            )
        );
        let new = response(&mut responses).await;
        assert_eq!(new["params"]["result"]["event"], "newBlock");
        assert_eq!(
            new["params"]["result"]["blockHash"],
            alloc::format!("0x{}", hex::encode(hash))
        );
        assert_eq!(
            response(&mut responses).await["params"]["result"]["event"],
            "bestBlockChanged"
        );
        let request = |method: &str, params: Value| {
            json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}).to_string()
        };
        client
            .json_rpc_request(
                request(
                    "chainHead_v1_header",
                    json!([id, alloc::format!("0x{}", hex::encode(hash))]),
                ),
                added.chain_id,
            )
            .unwrap();
        assert_eq!(
            response(&mut responses).await["result"],
            alloc::format!("0x{}", hex::encode(&header))
        );
        assert_eq!(blake2b_256(&header), hash);
        for (method, params) in [
            ("chainHead_v1_follow", json!([true])),
            ("system_health", json!([])),
            ("lifecycle_unstable_follow", json!([])),
        ] {
            client
                .json_rpc_request(request(method, params), added.chain_id)
                .unwrap();
            assert_eq!(response(&mut responses).await["error"]["code"], -32601);
        }
        client
            .json_rpc_request(
                request(
                    "chainHead_v1_unpin",
                    json!([id, [alloc::format!("0x{}", hex::encode(hash))]]),
                ),
                added.chain_id,
            )
            .unwrap();
        assert!(response(&mut responses).await["result"].is_null());
        client
            .json_rpc_request(
                request(
                    "chainHead_v1_header",
                    json!([id, alloc::format!("0x{}", hex::encode(hash))]),
                ),
                added.chain_id,
            )
            .unwrap();
        assert_eq!(response(&mut responses).await["error"]["code"], -32801);
        client
            .json_rpc_request(
                request("chainHead_v1_unfollow", json!([id])),
                added.chain_id,
            )
            .unwrap();
        assert!(response(&mut responses).await["result"].is_null());
        assert_eq!(platform.0.lock().unwrap().attempts, 2);
        // A known-parent announcement must not depend on CE128/body availability.
        assert_eq!(platform.0.lock().unwrap().requests.len(), 0);
        let config = Config::from_spec(&parsed).unwrap();
        let expected = jam_webtransport_cert::certificate_hashes(
            &config.peers[0].identity,
            platform.now_from_unix_epoch().as_secs(),
        );
        assert!(
            platform
                .0
                .lock()
                .unwrap()
                .pins
                .iter()
                .all(|pins| pins == &expected)
        );
        assert!(
            client
                .lifecycle_state(added.chain_id)
                .next()
                .await
                .is_none()
        );
        let () = client.remove_chain(added.chain_id);
        assert!(responses.next().await.is_none());
    });
}

#[test]
fn conservative_full_network_and_oversized_parameter_budgets() {
    let mut params = root_state().params;
    params.epoch_len = 600;
    params.max_validators = 1023;
    let (header, blocks) = memory_limits(&params).unwrap();
    let state = 600 * 160 + 1023 * 256 + 2048;
    assert!((blocks.get() * 2 + 3) * (header + state + 1024) <= TREE_BYTES);
    std::println!(
        "full-network budget: header={header}, state={state}, retained blocks={}, tree/transient ceiling={TREE_BYTES}",
        blocks.get()
    );
    params.epoch_len = u32::MAX;
    assert!(memory_limits(&params).is_err());
}

#[test]
fn all_foreground_requests_are_answered_without_substrate_handles() {
    smol::block_on(async {
        let state = root_state();
        let platform = FakePlatform(Arc::new(Mutex::new(Control {
            handshake: Vec::new(),
            responses: BTreeMap::new(),
            requests: Vec::new(),
            attempts: 0,
            fail_first: false,
            supported: false,
            pins: Vec::new(),
            disconnect: false,
            starve: false,
            queued: false,
            clock_shift: Duration::ZERO,
            io: IoState::default(),
        })));
        let service = Arc::new(super::super::SyncService::new_jam(
            platform,
            "test".into(),
            Config {
                params: state.params,
                tree: state.tree,
                peers: Vec::new(),
                header_bytes: 4096,
            },
        ));
        assert!(service.serialize_chain_information().await.is_none());
        assert!(!service.is_near_head_of_chain_heuristic().await);
        assert_eq!(service.syncing_peers().await.len(), 0);
        assert_eq!(
            service.peers_assumed_know_blocks(0, &[0; 32]).await.count(),
            0
        );
        assert_eq!(
            service.subscribe_sync_status().await.recv().await.unwrap(),
            SyncStatus::Ready
        );
        assert!(service.subscribe_all(1, true).await.new_blocks.is_closed());
        let fields = smoldot::network::codec::BlocksRequestFields {
            header: true,
            body: false,
            justifications: false,
        };
        assert!(
            service
                .clone()
                .block_query_unknown_number(
                    [0; 32],
                    fields.clone(),
                    1,
                    TIMEOUT,
                    core::num::NonZeroU32::MIN
                )
                .await
                .is_err()
        );
        assert!(
            service
                .block_query(0, [0; 32], fields, 1, TIMEOUT, core::num::NonZeroU32::MIN)
                .await
                .is_err()
        );
    });
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_untrusted_finality_catches_up_oldest_first_and_stops_slow_followers() {
    smol::block_on(async {
        let (platform, spec, _, _) = fixture_setup();
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let mut hashes = Vec::new();
        let mut last = None;
        for index in 0..36 {
            let raw = bytes(&fixture(&alloc::format!("headers/{index:04}.json"))["header_hex"]);
            let header = Header::decode(parsed.params(), &raw).unwrap();
            let hash = header.hash(parsed.params());
            let mut frame = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
            frame.extend(raw);
            if index != 0 {
                platform.0.lock().unwrap().responses.insert(hash, frame);
            }
            hashes.push(hash);
            last = Some(header);
        }
        let last = last.unwrap();
        let handshake = Handshake {
            final_: Final {
                hash: *hashes.last().unwrap(),
                slot: last.slot,
            },
            leaves: Vec::new(),
        }
        .encode();
        let mut frame = u32::try_from(handshake.len())
            .unwrap()
            .to_le_bytes()
            .to_vec();
        frame.extend(handshake);
        platform.0.lock().unwrap().handshake = frame;
        let config = Config::from_spec(&parsed).unwrap();
        let service =
            super::super::SyncService::new_jam(platform.clone(), "catchup".into(), config);
        let initial = service.subscribe_all(1, false).await;
        assert!(initial.non_finalized_blocks_ancestry_order.is_empty());
        future::or(
            async {
                while !initial.new_blocks.is_closed() {
                    smol::Timer::after(Duration::from_millis(1)).await;
                }
            },
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("slow subscription did not stop")
            },
        )
        .await;
        let block = future::or(async { initial.new_blocks.recv().await.unwrap() }, async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("catchup timed out")
        })
        .await;
        assert!(
            matches!(block, Notification::Block(ref b) if blake2b_256(&b.scale_encoded_header) == hashes[0])
        );
        assert!(initial.new_blocks.recv().await.is_err());
        // Replay is cooperative now: closing the slow subscriber does not imply
        // that the remaining ancestry has already been inserted.
        let snapshot = future::or(
            async {
                loop {
                    let snapshot = service.subscribe_all(16, false).await;
                    if snapshot.non_finalized_blocks_ancestry_order.len() == 36 {
                        break snapshot;
                    }
                    future::yield_now().await;
                }
            },
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("remaining ancestry was not replayed");
            },
        )
        .await;
        assert_eq!(snapshot.non_finalized_blocks_ancestry_order.len(), 36);
        assert_eq!(
            snapshot.finalized_block_scale_encoded_header,
            initial.finalized_block_scale_encoded_header
        );
        for (block, expected) in snapshot
            .non_finalized_blocks_ancestry_order
            .iter()
            .zip(&hashes)
        {
            assert_eq!(&blake2b_256(&block.scale_encoded_header), expected);
        }
        assert!(
            snapshot
                .non_finalized_blocks_ancestry_order
                .last()
                .unwrap()
                .is_new_best
        );
        let requested: Vec<_> = platform
            .0
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|r| r.hash)
            .collect();
        assert_eq!(
            requested,
            [0, 1, 3, 7, 15, 31]
                .into_iter()
                .map(|i| if i == 0 {
                    parsed.genesis_header().hash(parsed.params())
                } else {
                    hashes[i - 1]
                })
                .collect::<Vec<_>>()
        );
    });
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_verified_tree_memory_and_full_preserve_fixed_anchor() {
    let (_, spec, _, _) = fixture_setup();
    let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
    let config = Config::from_spec(&parsed).unwrap();
    let mut state = State {
        tree: config.tree,
        params: config.params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: config.header_bytes,
    };
    for index in 0..36 {
        let header = Header::decode(
            &state.params,
            &bytes(&fixture(&alloc::format!("headers/{index:04}.json"))["header_hex"]),
        )
        .unwrap();
        state.insert(header, 1_800_000_000).unwrap();
    }
    let measured: usize = state
        .tree
        .ancestry_order()
        .map(|block| {
            let state = &block.post_state;
            core::mem::size_of_val(block)
                + state.active.capacity()
                    * core::mem::size_of::<smoldot::jam::state::ValidatorPair>()
                + state.pending.capacity()
                    * core::mem::size_of::<smoldot::jam::state::ValidatorPair>()
                + match &state.sealing {
                    SealingSequence::Keys(keys) => keys.capacity() * 32,
                    SealingSequence::Tickets(tickets) => {
                        tickets.capacity() * core::mem::size_of::<smoldot::jam::types::Ticket>()
                    }
                }
                + state.pending_tickets.as_ref().map_or(0, |tickets| {
                    tickets.capacity() * core::mem::size_of::<smoldot::jam::types::Ticket>()
                })
                + block
                    .header
                    .epoch_mark
                    .as_ref()
                    .map_or(0, |mark| mark.validators.capacity() * 64)
                + block.header.tickets_mark.as_ref().map_or(0, |tickets| {
                    tickets.capacity() * core::mem::size_of::<smoldot::jam::types::Ticket>()
                })
                + block.header.offenders_mark.capacity() * 32
        })
        .sum();
    std::println!(
        "37 authenticated fixture nodes: {measured} measured inline/vector-capacity bytes (excludes allocator/ForkTree metadata); tree+transient ceiling={TREE_BYTES}"
    );
    assert!(measured * 2 < TREE_BYTES);
    let anchor = state.tree.finalized().clone();
    let mut full = State {
        tree: HeaderTree::new(
            state.params.clone(),
            anchor.clone(),
            tree::Config {
                max_blocks: core::num::NonZeroUsize::new(2).unwrap(),
            },
        ),
        params: state.params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: state.header_bytes,
    };
    let snapshot = full.subscribe(16, false);
    let first = Header::decode(
        &full.params,
        &bytes(&fixture("headers/0000.json")["header_hex"]),
    )
    .unwrap();
    let second = Header::decode(
        &full.params,
        &bytes(&fixture("headers/0001.json")["header_hex"]),
    )
    .unwrap();
    full.insert(first, 1_800_000_000).unwrap();
    assert!(full.insert(second, 1_800_000_000).is_err());
    assert!(full.stopped && snapshot.new_blocks.is_closed());
    assert!(matches!(
        snapshot.new_blocks.try_recv(),
        Ok(Notification::Block(_))
    ));
    assert!(snapshot.new_blocks.try_recv().is_err());
    assert_eq!(full.tree.finalized(), &anchor);
    assert!(full.subscribe(16, false).new_blocks.is_closed());
}

#[test]
#[ignore = "requires external A5 configuration; JAM_A5_FIXTURES or planning checkout"]
fn external_invalid_identity_is_propagated_before_startup_and_capability_is_guarded() {
    smol::block_on(async {
        let (platform, raw, _, _) = fixture_setup();
        let mut spec: Value = serde_json::from_str(&raw).unwrap();
        spec["bootnodes"] = json!([alloc::format!(
            "e{}+v{}b@127.0.0.1:4433",
            "a".repeat(52),
            "7".repeat(51)
        )]);
        // The text is valid, but X = 2^256 - 1 is outside the P-256 field.
        assert!(JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).is_ok());
        let invalid = spec.to_string();
        let mut client = Client::new(platform.clone());
        let add = |specification| AddChainConfig {
            specification,
            user_data: (),
            database_content: "",
            potential_relay_chains: core::iter::empty(),
            json_rpc: AddChainConfigJsonRpc::Disabled,
            statement_protocol_config: None,
        };
        let error = match client.add_chain(add(&invalid)) {
            Err(error) => error,
            Ok(_) => panic!("invalid identity accepted"),
        };
        assert!(error.to_string().contains("P256"));
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        spec["bootnodes"] = json!([alloc::format!("e{}@127.0.0.1:4433", "a".repeat(52))]);
        let ed_only = spec.to_string();
        let parsed = JamChainSpec::from_json_bytes(ed_only.as_bytes()).unwrap();
        assert!(Config::from_spec(&parsed).unwrap().peers.is_empty());
        let added = client.add_chain(add(&ed_only)).unwrap();
        smol::Timer::after(Duration::from_millis(10)).await;
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        let () = client.remove_chain(added.chain_id);
        platform.0.lock().unwrap().supported = false;
        let added = client.add_chain(add(&raw)).unwrap();
        smol::Timer::after(Duration::from_millis(10)).await;
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        let () = client.remove_chain(added.chain_id);
    });
}

fn framed(payload: Vec<u8>) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    frame.extend(payload);
    frame
}

fn fixture_header(params: &Params, index: usize) -> Header {
    Header::decode(
        params,
        &bytes(&fixture(&alloc::format!("headers/{index:04}.json"))["header_hex"]),
    )
    .unwrap()
}

async fn until(mut condition: impl FnMut() -> bool) {
    future::or(
        async {
            while !condition() {
                smol::Timer::after(Duration::from_millis(1)).await;
            }
        },
        async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("condition timed out")
        },
    )
    .await;
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_missing_parent_announcement_retained_and_captured_ce128_used() {
    smol::block_on(async {
        let (platform, spec, first_hash, _) = fixture_setup();
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let child = fixture_header(parsed.params(), 1);
        let child_hash = child.hash(parsed.params());
        let mut frames = bytes(&fixture("messages/up0.json")["handshake_frame_hex"]);
        frames.extend(framed(
            smoldot::jam::types::Announcement {
                header: child,
                final_: Final {
                    hash: parsed.genesis_header().hash(parsed.params()),
                    slot: 0,
                },
            }
            .encode(parsed.params()),
        ));
        platform.0.lock().unwrap().handshake = frames;
        let service = super::super::SyncService::new_jam(
            platform.clone(),
            "announcement-parent".into(),
            Config::from_spec(&parsed).unwrap(),
        );
        let snapshot = service.subscribe_all(16, false).await;
        until(|| platform.0.lock().unwrap().requests.len() == 1).await;
        let mut initial = snapshot.non_finalized_blocks_ancestry_order.into_iter();
        for expected in [first_hash, child_hash] {
            let notification = future::or(
                async {
                    if let Some(block) = initial.next() {
                        Notification::Block(block)
                    } else {
                        snapshot.new_blocks.recv().await.unwrap()
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("missing ancestor notification")
                },
            )
            .await;
            assert!(
                matches!(notification, Notification::Block(ref block) if blake2b_256(&block.scale_encoded_header) == expected)
            );
        }
        assert_eq!(platform.0.lock().unwrap().requests[0].hash, first_hash);
        assert_eq!(platform.0.lock().unwrap().requests.len(), 1);
    });
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_established_disconnect_reconnect_catches_up_without_finalizing() {
    smol::block_on(async {
        let (platform, spec, first_hash, _) = fixture_setup();
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let service = super::super::SyncService::new_jam(
            platform.clone(),
            "established-reconnect".into(),
            Config::from_spec(&parsed).unwrap(),
        );
        let snapshot = service.subscribe_all(16, false).await;
        let first = future::or(async { snapshot.new_blocks.recv().await.unwrap() }, async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("initial sync timed out")
        })
        .await;
        assert!(
            matches!(first, Notification::Block(ref block) if blake2b_256(&block.scale_encoded_header) == first_hash)
        );
        let second = fixture_header(parsed.params(), 1);
        let third = fixture_header(parsed.params(), 2);
        let second_hash = second.hash(parsed.params());
        let third_hash = third.hash(parsed.params());
        {
            let mut c = platform.0.lock().unwrap();
            c.responses
                .insert(second_hash, framed(second.encode(parsed.params())));
            c.responses
                .insert(third_hash, framed(third.encode(parsed.params())));
            c.handshake = framed(
                Handshake {
                    final_: Final {
                        hash: third_hash,
                        slot: third.slot,
                    },
                    leaves: Vec::new(),
                }
                .encode(),
            );
            c.disconnect = true;
        }
        for expected in [second_hash, third_hash] {
            let notification =
                future::or(async { snapshot.new_blocks.recv().await.unwrap() }, async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("reconnect catchup timed out")
                })
                .await;
            assert!(
                matches!(notification, Notification::Block(ref block) if blake2b_256(&block.scale_encoded_header) == expected)
            );
        }
        assert_eq!(platform.0.lock().unwrap().attempts, 2);
        assert_eq!(
            platform
                .0
                .lock()
                .unwrap()
                .requests
                .iter()
                .map(|r| r.hash)
                .collect::<Vec<_>>(),
            vec![first_hash, second_hash]
        );
        assert_eq!(
            service
                .subscribe_all(1, false)
                .await
                .finalized_block_scale_encoded_header,
            snapshot.finalized_block_scale_encoded_header
        );
    });
}

#[test]
#[ignore = "requires external A5 configuration; JAM_A5_FIXTURES or planning checkout"]
fn external_queued_request_and_unidentified_streams_cannot_starve_deadlines() {
    smol::block_on(async {
        let (platform, spec, hash, _) = fixture_setup();
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let header = fixture_header(parsed.params(), 0);
        {
            let mut c = platform.0.lock().unwrap();
            c.handshake = framed(
                Handshake {
                    final_: Final {
                        hash,
                        slot: header.slot,
                    },
                    leaves: Vec::new(),
                }
                .encode(),
            );
            c.starve = true;
        }
        let service = super::super::SyncService::new_jam(
            platform.clone(),
            "queued-deadline".into(),
            Config::from_spec(&parsed).unwrap(),
        );
        let snapshot = service.subscribe_all(16, false).await;
        until(|| platform.0.lock().unwrap().queued).await;
        {
            let mut c = platform.0.lock().unwrap();
            assert_eq!(
                c.requests.len(),
                0,
                "CE must still be queued behind the unidentified streams"
            );
            c.clock_shift = Duration::from_secs(21);
            c.starve = false;
        }
        until(|| platform.0.lock().unwrap().attempts >= 2).await;
        assert_eq!(
            service
                .subscribe_all(1, false)
                .await
                .finalized_block_scale_encoded_header,
            snapshot.finalized_block_scale_encoded_header
        );
        let notification = future::or(async { snapshot.new_blocks.recv().await.unwrap() }, async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("post-timeout sync timed out")
        })
        .await;
        assert!(
            matches!(notification, Notification::Block(ref block) if blake2b_256(&block.scale_encoded_header) == hash)
        );
    });
}

#[test]
#[ignore = "requires external A5 checkpoint; JAM_A5_FIXTURES or planning checkout"]
fn external_genesis_and_checkpoint_configs_use_complete_anchor_state() {
    let (_, raw, _, _) = fixture_setup();
    let genesis_spec = JamChainSpec::from_json_bytes(raw.as_bytes()).unwrap();
    let genesis_config = Config::from_spec(&genesis_spec).unwrap();
    assert_eq!(
        genesis_config.tree.finalized().post_state,
        LightState::from_anchor(genesis_spec.params(), genesis_spec.genesis_light_state()).unwrap(),
    );
    for (case, index) in checkpoint_cases(genesis_spec.params())
        .into_iter()
        .enumerate()
    {
        let mut spec: Value = serde_json::from_str(&raw).unwrap();
        spec["checkpoint"] = checkpoint_fixture(index);
        let encoded = spec.to_string();
        let parsed = JamChainSpec::from_json_bytes(encoded.as_bytes()).unwrap();
        let checkpoint = parsed.checkpoint().unwrap();
        let fixture = fixture(&alloc::format!("headers/{index:04}.json"));
        let raw_state = raw_fixture_state(parsed.params(), &fixture["post_light_state"]);
        assert_eq!(checkpoint.state, raw_state);
        let config = Config::from_spec(&parsed).unwrap();
        assert_eq!(
            config.tree.finalized().post_state,
            LightState::from_anchor(parsed.params(), &raw_state).unwrap(),
            "fixture {index:04}",
        );
        assert_eq!(config.tree.finalized().header, checkpoint.header);
        assert_eq!(config.tree.len(), 1);
        let epoch_len = usize::try_from(parsed.params().epoch_len).unwrap();
        match case {
            0 => {
                assert!(
                    raw_state.slot % parsed.params().epoch_len >= parsed.params().epoch_tail_start
                );
                assert!(raw_state.safrole.ticket_accumulator.len() < epoch_len);
                assert!(config.tree.finalized().post_state.pending_tickets.is_none());
            }
            1 => {
                assert!(
                    raw_state.slot % parsed.params().epoch_len < parsed.params().epoch_tail_start
                );
                assert_eq!(raw_state.safrole.ticket_accumulator.len(), epoch_len);
                assert!(config.tree.finalized().post_state.pending_tickets.is_none());
            }
            2 => {
                assert_eq!(raw_state.safrole.ticket_accumulator.len(), epoch_len);
                assert!(
                    raw_state
                        .safrole
                        .ticket_accumulator
                        .windows(2)
                        .all(|pair| pair[0].id < pair[1].id)
                );
                // The captured winners mark is already sequenced. C1 passes the
                // raw accumulator to B3, rather than calculating or repeating Z.
                let winners = (0..=index)
                    .rev()
                    .find_map(|i| {
                        let header = fixture_header(parsed.params(), i);
                        (header.slot / parsed.params().epoch_len
                            == raw_state.slot / parsed.params().epoch_len)
                            .then_some(header.tickets_mark)
                            .flatten()
                    })
                    .expect("captured winners mark in checkpoint epoch");
                assert_eq!(
                    config.tree.finalized().post_state.pending_tickets.as_ref(),
                    Some(&winners)
                );
                assert_ne!(winners, raw_state.safrole.ticket_accumulator);
            }
            _ => unreachable!(),
        }
    }
}

fn raw_fixture_state(params: &Params, fixture: &Value) -> GenesisLightState {
    let items: Vec<([u8; 31], Vec<u8>)> = fixture["state_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                bytes(&item["key_hex"]).try_into().unwrap(),
                bytes(&item["value_hex"]),
            )
        })
        .collect();
    GenesisLightState::from_state_items(
        params,
        items.iter().map(|(key, value)| (key, value.as_slice())),
    )
    .unwrap()
}

#[test]
#[ignore = "requires external A5 signed checkpoint fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_tail_checkpoint_tree_replays_complete_ticket_epoch() {
    let (_, raw, _, _) = fixture_setup();
    let mut spec: Value = serde_json::from_str(&raw).unwrap();
    let genesis_spec = JamChainSpec::from_json_bytes(raw.as_bytes()).unwrap();
    let anchor_index = checkpoint_cases(genesis_spec.params())[2];
    let epoch_len = usize::try_from(genesis_spec.params().epoch_len).unwrap();
    spec["checkpoint"] = checkpoint_fixture(anchor_index);
    let parsed = JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).unwrap();
    let mut config = Config::from_spec(&parsed).unwrap();
    let anchor = config.tree.finalized().clone();
    let mut reference = verified_genesis(
        parsed.params(),
        parsed.genesis_header().clone(),
        LightState::from_anchor(parsed.params(), parsed.genesis_light_state()).unwrap(),
    );
    for index in 0..=anchor_index {
        reference = smoldot::jam::verify::verify_header(
            parsed.params(),
            &reference,
            fixture_header(parsed.params(), index),
            1_800_000_000,
        )
        .unwrap();
    }
    assert_eq!(anchor.hash, reference.hash);
    assert_eq!(anchor.post_state, reference.post_state);
    for index in anchor_index + 1..=anchor_index + epoch_len {
        let fixture = fixture(&alloc::format!("headers/{index:04}.json"));
        let header = Header::decode(parsed.params(), &bytes(&fixture["header_hex"])).unwrap();
        reference = smoldot::jam::verify::verify_header(
            parsed.params(),
            &reference,
            header.clone(),
            1_800_000_000,
        )
        .unwrap();
        config
            .tree
            .insert(header.parent, header, 1_800_000_000)
            .unwrap();
        let block = config.tree.get(&reference.hash).unwrap();
        assert_eq!(block, &reference, "header {index:04}");
        assert!(block.sealed_with_ticket, "header {index:04}");
        assert_eq!(block.hash.as_slice(), bytes(&fixture["header_hash"]));
        assert_eq!(
            block.post_state,
            LightState::from_anchor(
                parsed.params(),
                &raw_fixture_state(parsed.params(), &fixture["post_light_state"])
            )
            .unwrap()
        );
        assert_eq!(config.tree.finalized(), &anchor);
    }
    assert_eq!(config.tree.len(), epoch_len + 1);
}

#[test]
#[ignore = "requires external A5 anchor state; JAM_A5_FIXTURES or planning checkout"]
fn external_oversized_anchor_accumulator_preserves_constructor_and_parser_errors() {
    let (platform, raw, _, _) = fixture_setup();
    let mut spec: Value = serde_json::from_str(&raw).unwrap();
    let genesis_spec = JamChainSpec::from_json_bytes(raw.as_bytes()).unwrap();
    spec["checkpoint"] = checkpoint_fixture(checkpoint_cases(genesis_spec.params())[2]);
    let parsed = JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).unwrap();
    let mut raw_state = parsed.checkpoint().unwrap().state.clone();
    raw_state
        .safrole
        .ticket_accumulator
        .push(raw_state.safrole.ticket_accumulator[0].clone());
    assert_eq!(
        LightState::from_anchor(parsed.params(), &raw_state),
        Err(smoldot::jam::state::StateError::TicketAccumulatorTooLong)
    );
    assert_eq!(
        Config::anchor_state(parsed.params(), &raw_state).unwrap_err(),
        "JAM starting state: TicketAccumulatorTooLong"
    );
    // The public parser enforces the same count bound first. Keep that error
    // intact rather than changing the parser merely to reach the constructor.
    spec["checkpoint"]["state"]["safrole"] =
        json!(hex::encode(raw_state.safrole.encode(parsed.params())));
    let error = rejected_add_chain_without_startup(&platform, &spec.to_string());
    assert!(error.contains("checkpoint.state.safrole"), "{error}");
}

// The capture starts at the current wall-clock phase. Select all three checkpoint
// shapes from native post-state rather than encoding one run's file numbers.
fn checkpoint_cases(params: &Params) -> [usize; 3] {
    let headers: Vec<_> = (0..36)
        .map(|i| fixture(&alloc::format!("headers/{i:04}.json")))
        .collect();
    let epoch_len = usize::try_from(params.epoch_len).unwrap();
    let states: Vec<_> = headers
        .iter()
        .map(|h| raw_fixture_state(params, &h["post_light_state"]))
        .collect();
    let incomplete_tail = states
        .iter()
        .position(|state| {
            state.slot % params.epoch_len >= params.epoch_tail_start
                && state.safrole.ticket_accumulator.len() < epoch_len
        })
        .expect("capture needs a non-saturated tail checkpoint");
    let saturated_before_tail = states
        .iter()
        .position(|state| {
            state.slot % params.epoch_len < params.epoch_tail_start
                && state.safrole.ticket_accumulator.len() == epoch_len
        })
        .expect("capture needs a saturated pre-tail checkpoint");
    let saturated_tail = states
        .iter()
        .enumerate()
        .find_map(|(i, state)| {
            (state.slot % params.epoch_len == params.epoch_len - 1
                && state.safrole.ticket_accumulator.len() == epoch_len
                && headers.get(i + 1..i + 1 + epoch_len).is_some_and(|epoch| {
                    epoch.iter().enumerate().all(|(offset, h)| {
                        h["seal_mode"] == "ticket"
                            && h["slot"].as_u64().unwrap()
                                == u64::from(state.slot) + 1 + u64::try_from(offset).unwrap()
                    })
                }))
            .then_some(i)
        })
        .expect("capture needs a tail checkpoint followed by a complete ticket epoch");
    [incomplete_tail, saturated_before_tail, saturated_tail]
}

fn checkpoint_fixture(index: usize) -> Value {
    let checkpoint = fixture(&alloc::format!("headers/{index:04}.json"));
    let items = checkpoint["post_light_state"]["state_items"]
        .as_array()
        .unwrap();
    let item =
        |index: u8| items.iter().find(|item| item["index"] == index).unwrap()["value_hex"].clone();
    json!({"header":checkpoint["header_hex"], "state":{"safrole":item(4),"entropy":item(6),"active_validators":item(8),"slot":item(11)}})
}

fn rejected_add_chain_without_startup(platform: &FakePlatform, specification: &str) -> String {
    let mut client = Client::new(platform.clone());
    let error = match client.add_chain(AddChainConfig {
        specification,
        user_data: (),
        database_content: "",
        potential_relay_chains: core::iter::empty(),
        json_rpc: AddChainConfigJsonRpc::Enabled {
            max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
            max_subscriptions: 2,
        },
        statement_protocol_config: None,
    }) {
        Err(crate::AddChainError::Jam(error)) => error,
        Err(error) => panic!("unexpected add_chain error: {error}"),
        Ok(_) => panic!("invalid JAM configuration was accepted"),
    };
    assert!(client.public_api_chains.is_empty());
    assert!(client.chains_by_key.is_none());
    assert!(client.network_service.is_none());
    let c = platform.0.lock().unwrap();
    assert_eq!(c.attempts, 0);
    assert_eq!(c.io.tasks_spawned, 0);
    assert_eq!(c.io.live_tasks, 0);
    assert_eq!(c.io.live_connections, 0);
    assert_eq!(c.io.live_streams, 0);
    error
}

#[test]
#[ignore = "requires external A5 state fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_malformed_genesis_and_checkpoint_state_errors_are_propagated() {
    for checkpoint in [false, true] {
        let (platform, raw, _, _) = fixture_setup();
        let mut spec: Value = serde_json::from_str(&raw).unwrap();
        let expected_field = if checkpoint {
            spec["checkpoint"] = checkpoint_fixture(13);
            spec["checkpoint"]["state"]["slot"] = json!("00");
            "checkpoint.state.slot"
        } else {
            let key = hex::encode(smoldot::jam::codec::state_key(11));
            spec["genesis_state"][key] = json!("00");
            "genesis_state.slot"
        };
        let error = rejected_add_chain_without_startup(&platform, &spec.to_string());
        assert!(error.contains(expected_field), "{error}");
    }
}

// Mock only the sync/RPC boundary so snapshot forks can be tested without
// constructing or bypassing consensus verification. The RPC frontend is real.
fn rpc_snapshot(
    blocks: Vec<BlockNotification>,
) -> (
    crate::json_rpc_service::Frontend<FakePlatform>,
    async_channel::Sender<Notification>,
    Vec<u8>,
) {
    let platform = FakePlatform(Arc::new(Mutex::new(Control {
        handshake: Vec::new(),
        responses: BTreeMap::new(),
        requests: Vec::new(),
        attempts: 0,
        fail_first: false,
        supported: false,
        pins: Vec::new(),
        disconnect: false,
        starve: false,
        queued: false,
        clock_shift: Duration::ZERO,
        io: IoState::default(),
    })));
    let root = vec![0];
    let (notifications, new_blocks) = async_channel::bounded(16);
    let (to_background, requests) = async_channel::bounded(16);
    let sync_service = Arc::new(super::super::SyncService {
        to_background,
        platform: platform.clone(),
        network_service: None,
        block_number_bytes: 4,
    });
    platform.spawn_task("rpc-snapshot-test".into(), {
        let root = root.clone();
        async move {
            while let Ok(request) = requests.recv().await {
                let ToBackground::SubscribeAll {
                    send_back,
                    runtime_interest,
                    ..
                } = request
                else {
                    panic!("unexpected request to mock sync service");
                };
                assert!(!runtime_interest);
                let _ = send_back.send(SubscribeAll {
                    finalized_block_scale_encoded_header: root.clone(),
                    finalized_block_runtime: None,
                    non_finalized_blocks_ancestry_order: blocks.clone(),
                    new_blocks: new_blocks.clone(),
                });
            }
        }
    });
    let frontend = crate::json_rpc_service::service(crate::json_rpc_service::Config::Jam(
        crate::json_rpc_service::JamConfig {
            platform,
            log_name: "snapshot-test".into(),
            sync_service,
            max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
            max_subscriptions: 2,
        },
    ));
    (frontend, notifications, root)
}

async fn rpc_message(frontend: &crate::json_rpc_service::Frontend<FakePlatform>) -> Value {
    let text = future::or(frontend.next_json_rpc_response(), async {
        smol::Timer::after(Duration::from_secs(3)).await;
        panic!("RPC message timed out");
    })
    .await;
    serde_json::from_str(&text).unwrap()
}

async fn rpc_call(
    frontend: &crate::json_rpc_service::Frontend<FakePlatform>,
    method: &str,
    params: Value,
) -> Value {
    frontend
        .queue_rpc_request(
            json!({"jsonrpc":"2.0", "id":7, "method":method, "params":params}).to_string(),
        )
        .unwrap();
    let reply = rpc_message(frontend).await;
    // A request after snapshot delivery also detects extra snapshot notifications.
    assert_eq!(reply["id"], 7, "unexpected notification: {reply}");
    reply
}

fn rpc_hash(bytes: &[u8]) -> String {
    alloc::format!("0x{}", hex::encode(blake2b_256(bytes)))
}

async fn rpc_follow_snapshot(
    frontend: &crate::json_rpc_service::Frontend<FakePlatform>,
    root: &[u8],
    blocks: &[BlockNotification],
    best: &[u8],
) -> String {
    let reply = rpc_call(frontend, "chainHead_v1_follow", json!([false])).await;
    let id = reply["result"].as_str().unwrap().to_owned();
    let initialized = rpc_message(frontend).await;
    assert_eq!(initialized["params"]["subscription"], id);
    assert_eq!(
        initialized["params"]["result"],
        json!({"event":"initialized", "finalizedBlockHashes":[rpc_hash(root)]})
    );
    for block in blocks {
        let event = rpc_message(frontend).await;
        assert_eq!(event["params"]["subscription"], id);
        assert_eq!(event["params"]["result"]["event"], "newBlock");
        assert_eq!(
            event["params"]["result"]["blockHash"],
            rpc_hash(&block.scale_encoded_header)
        );
        assert_eq!(
            event["params"]["result"]["parentBlockHash"],
            alloc::format!("0x{}", hex::encode(block.parent_hash))
        );
    }
    let best_event = rpc_message(frontend).await;
    assert_eq!(best_event["params"]["subscription"], id);
    assert_eq!(
        best_event["params"]["result"],
        json!({"event":"bestBlockChanged", "bestBlockHash":rpc_hash(best)})
    );
    id
}

#[test]
fn jam_rpc_root_only_snapshot_reports_best_once_and_keeps_anchor_pinned() {
    smol::block_on(async {
        let (frontend, _notifications, root) = rpc_snapshot(Vec::new());
        let id = rpc_follow_snapshot(&frontend, &root, &[], &root).await;
        let reply = rpc_call(
            &frontend,
            "chainHead_v1_header",
            json!([id, rpc_hash(&root)]),
        )
        .await;
        assert_eq!(reply["result"], alloc::format!("0x{}", hex::encode(&root)));
    });
}

#[test]
fn jam_rpc_fork_snapshot_reports_all_blocks_before_best_and_preserves_live_order() {
    smol::block_on(async {
        let blocks = vec![
            BlockNotification {
                is_new_best: true,
                scale_encoded_header: vec![1],
                parent_hash: blake2b_256(&[0]),
            },
            BlockNotification {
                is_new_best: false,
                scale_encoded_header: vec![2],
                parent_hash: blake2b_256(&[0]),
            },
            BlockNotification {
                is_new_best: false,
                scale_encoded_header: vec![3],
                parent_hash: blake2b_256(&[2]),
            },
        ];
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, &[1]).await;
        for block in &blocks {
            let reply = rpc_call(
                &frontend,
                "chainHead_v1_header",
                json!([id, rpc_hash(&block.scale_encoded_header)]),
            )
            .await;
            assert_eq!(
                reply["result"],
                alloc::format!("0x{}", hex::encode(&block.scale_encoded_header))
            );
        }
        notifications
            .try_send(Notification::Block(BlockNotification {
                is_new_best: true,
                scale_encoded_header: vec![4],
                parent_hash: blake2b_256(&[3]),
            }))
            .unwrap();
        let live_block = rpc_message(&frontend).await;
        assert_eq!(live_block["params"]["result"]["event"], "newBlock");
        assert_eq!(live_block["params"]["result"]["blockHash"], rpc_hash(&[4]));
        assert_eq!(
            live_block["params"]["result"]["parentBlockHash"],
            rpc_hash(&[3])
        );
        assert_eq!(
            rpc_message(&frontend).await["params"]["result"],
            json!({"event":"bestBlockChanged", "bestBlockHash":rpc_hash(&[4])})
        );
        assert_eq!(
            rpc_call(
                &frontend,
                "chainHead_v1_header",
                json!([id, rpc_hash(&[4])])
            )
            .await["result"],
            "0x04"
        );
    });
}

#[test]
fn jam_rpc_unpin_unknown_and_already_unpinned_are_32801_and_batches_are_atomic() {
    smol::block_on(async {
        let blocks = vec![BlockNotification {
            is_new_best: true,
            scale_encoded_header: vec![1],
            parent_hash: blake2b_256(&[0]),
        }];
        let (frontend, _notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, &[1]).await;
        let known = rpc_hash(&[1]);
        let unknown = rpc_hash(&[99]);
        for hashes in [json!(unknown), json!([known, unknown])] {
            assert_eq!(
                rpc_call(&frontend, "chainHead_v1_unpin", json!([id, hashes])).await["error"]["code"],
                -32801
            );
            assert_eq!(
                rpc_call(&frontend, "chainHead_v1_header", json!([id, known])).await["result"],
                "0x01"
            );
        }
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_unpin", json!([id, [known, known]])).await["error"]["code"],
            -32804
        );
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_header", json!([id, known])).await["result"],
            "0x01"
        );
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_unpin", json!([id, known]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
        for hashes in [json!(known), json!([rpc_hash(&root), known])] {
            assert_eq!(
                rpc_call(&frontend, "chainHead_v1_unpin", json!([id, hashes])).await["error"]["code"],
                -32801
            );
            assert_eq!(
                rpc_call(
                    &frontend,
                    "chainHead_v1_header",
                    json!([id, rpc_hash(&root)])
                )
                .await["result"],
                "0x00"
            );
        }
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_unpin", json!([id, 42])).await["error"]["code"],
            -32602
        );
        assert_eq!(
            rpc_call(
                &frontend,
                "chainHead_v1_unpin",
                json!(["unknown-subscription", unknown])
            )
            .await
            .get("result"),
            Some(&Value::Null)
        );
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_unfollow", json!([id]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
        assert_eq!(
            rpc_call(&frontend, "chainHead_v1_unpin", json!([id, unknown]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
    });
}

fn event_driven_fixture(
    executor: &Arc<smol::Executor<'static>>,
    peers: usize,
) -> (FakePlatform, String, Vec<Header>) {
    let (platform, spec, _, _) = fixture_setup();
    let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
    let headers: Vec<_> = (0..36)
        .map(|index| fixture_header(parsed.params(), index))
        .collect();
    let tip = headers.last().unwrap();
    {
        let mut c = platform.0.lock().unwrap();
        c.io.event_driven = true;
        c.io.executor = Some(executor.clone());
        for header in headers.iter().skip(1) {
            c.responses.insert(
                header.hash(parsed.params()),
                framed(header.encode(parsed.params())),
            );
        }
        c.handshake = framed(
            Handshake {
                final_: Final {
                    hash: tip.hash(parsed.params()),
                    slot: tip.slot,
                },
                leaves: Vec::new(),
            }
            .encode(),
        );
    }
    let mut spec: Value = serde_json::from_str(&spec).unwrap();
    let first = spec["bootnodes"][0].as_str().unwrap();
    let identity = first.split_once('@').unwrap().0.to_owned();
    spec["bootnodes"] = json!(
        (0..peers)
            .map(|index| alloc::format!("{identity}@127.0.0.1:{}", 4433 + index))
            .collect::<Vec<_>>()
    );
    (platform, spec.to_string(), headers)
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_active_rpc_survives_large_catchup_with_one_and_two_event_driven_peers() {
    for peers in [1, 2] {
        // Like the browser, producers and the RPC consumer share one thread.
        let executor = Arc::new(smol::Executor::new());
        let scenario_executor = executor.clone();
        let scenario = executor.spawn(async move {
            let (platform, spec, headers) = event_driven_fixture(&scenario_executor, peers);
            let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
            let root = parsed.genesis_header().hash(parsed.params());
            let mut client = Client::new(platform.clone());
            let added = client.add_chain(AddChainConfig {
                specification: &spec,
                user_data: (),
                database_content: "",
                potential_relay_chains: core::iter::empty(),
                json_rpc: AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
                    max_subscriptions: 2,
                },
                statement_protocol_config: None,
            }).unwrap();
            let mut responses = added.json_rpc_responses.unwrap();
            client.json_rpc_request(r#"{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[false]}"#, added.chain_id).unwrap();
            let id = response(&mut responses).await["result"].as_str().unwrap().to_owned();
            let initialized = response(&mut responses).await;
            assert_eq!(initialized["params"]["result"]["event"], "initialized");
            assert_eq!(initialized["params"]["result"]["finalizedBlockHashes"], json!([alloc::format!("0x{}", hex::encode(root))]));
            let initial_best = response(&mut responses).await;
            assert_eq!(initial_best["params"]["result"]["event"], "bestBlockChanged");
            assert_eq!(initial_best["params"]["result"]["bestBlockHash"], alloc::format!("0x{}", hex::encode(root)));
            for header in &headers {
                let hash = alloc::format!("0x{}", hex::encode(header.hash(parsed.params())));
                let block = response(&mut responses).await;
                assert_eq!(block["params"]["subscription"], id);
                assert_eq!(block["params"]["result"]["event"], "newBlock");
                assert_eq!(block["params"]["result"]["blockHash"], hash);
                assert_eq!(block["params"]["result"]["parentBlockHash"], alloc::format!("0x{}", hex::encode(header.parent)));
                let best = response(&mut responses).await;
                assert_eq!(best["params"]["result"], json!({"event":"bestBlockChanged", "bestBlockHash":hash}));
            }
            let tip = headers.last().unwrap();
            client.json_rpc_request(json!({"jsonrpc":"2.0", "id":2, "method":"chainHead_v1_header", "params":[id, alloc::format!("0x{}", hex::encode(tip.hash(parsed.params())))]}).to_string(), added.chain_id).unwrap();
            let reply = response(&mut responses).await;
            assert_eq!(reply["id"], 2, "duplicate or stop event after catch-up: {reply}");
            assert_eq!(reply["result"], alloc::format!("0x{}", hex::encode(tip.encode(parsed.params()))));
            until(|| { let c = platform.0.lock().unwrap();
                c.io.pending_waits != 0 && c.io.live_streams == peers
            }).await;
            {
                let c = platform.0.lock().unwrap();
                assert_eq!(c.attempts, peers);
                assert!(c.requests.len() >= 6);
                assert!(c.requests.iter().all(|request| (1..=64).contains(&request.max_blocks) && request.direction == Direction::AscendingExclusive));
                assert_eq!(c.io.live_connections, peers);
                assert_eq!(c.io.live_streams, peers, "completed CE128 streams must be retired");
            }
            let () = client.remove_chain(added.chain_id);
            assert!(responses.next().await.is_none());
            until(|| {
                let c = platform.0.lock().unwrap();
                c.io.live_tasks == 0 && c.io.live_connections == 0 && c.io.live_streams == 0
            }).await;
        });
        smol::block_on(executor.run(scenario));
    }
}

#[test]
#[ignore = "requires external A5 signed fixtures; JAM_A5_FIXTURES or planning checkout"]
fn external_coalesced_up0_frames_progress_without_fresh_readiness_edges() {
    let executor = Arc::new(smol::Executor::new());
    let scenario_executor = executor.clone();
    let scenario = executor.spawn(async move {
        let (platform, spec, headers) = event_driven_fixture(&scenario_executor, 1);
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let root = parsed.genesis_header().hash(parsed.params());
        let mut frames = bytes(&fixture("messages/up0.json")["handshake_frame_hex"]);
        for header in &headers {
            frames.extend(framed(smoldot::jam::types::Announcement {
                header: header.clone(), final_: Final { hash: root, slot: 0 },
            }.encode(parsed.params())));
        }
        platform.0.lock().unwrap().handshake = frames;
        let service = super::super::SyncService::new_jam(platform.clone(), "coalesced-up0".into(), Config::from_spec(&parsed).unwrap());
        let snapshot = service.subscribe_all(16, false).await;
        assert!(snapshot.non_finalized_blocks_ancestry_order.is_empty());
        for header in &headers {
            let notification = future::or(async { snapshot.new_blocks.recv().await.unwrap() }, async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("buffered UP0 frame waited for a nonexistent readiness edge");
            }).await;
            assert!(matches!(notification, Notification::Block(ref block) if blake2b_256(&block.scale_encoded_header) == header.hash(parsed.params()) && block.parent_hash == header.parent));
        }
        assert!(!snapshot.new_blocks.is_closed());
        assert!(snapshot.new_blocks.try_recv().is_err());
        assert!(platform.0.lock().unwrap().requests.is_empty());
        until(|| platform.0.lock().unwrap().io.pending_waits != 0).await;
        drop(service);
        until(|| {
            let c = platform.0.lock().unwrap();
            c.io.live_tasks == 0 && c.io.live_connections == 0 && c.io.live_streams == 0
        }).await;
        assert!(snapshot.new_blocks.is_closed());
    });
    smol::block_on(executor.run(scenario));
}

#[test]
#[ignore = "requires external A5 configuration; JAM_A5_FIXTURES or planning checkout"]
fn external_shutdown_cancels_pending_opening_without_timer_or_io_wakeup() {
    let executor = Arc::new(smol::Executor::new());
    let scenario_executor = executor.clone();
    let scenario = executor.spawn(async move {
        let (platform, spec, _) = event_driven_fixture(&scenario_executor, 1);
        platform.0.lock().unwrap().io.stall_outbound = true;
        let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
        let service = super::super::SyncService::new_jam(
            platform.clone(),
            "pending-open-shutdown".into(),
            Config::from_spec(&parsed).unwrap(),
        );
        let snapshot = service.subscribe_all(16, false).await;
        until(|| {
            let c = platform.0.lock().unwrap();
            c.io.stalled_openings == 1 && c.io.pending_waits != 0
        })
        .await;
        assert!(platform.0.lock().unwrap().requests.is_empty());
        assert!(snapshot.new_blocks.try_recv().is_err());
        drop(service);
        until(|| {
            let c = platform.0.lock().unwrap();
            c.io.live_tasks == 0 && c.io.live_connections == 0 && c.io.live_streams == 0
        })
        .await;
        assert!(snapshot.new_blocks.is_closed());
    });
    smol::block_on(executor.run(scenario));
}

#[test]
#[ignore = "requires external A5 signed checkpoints; JAM_A5_FIXTURES or planning checkout"]
fn external_checkpoint_public_follow_header_and_older_peer_finality() {
    // Actual raw checkpoints cover a non-saturated tail, a saturated pre-tail,
    // and the saturated tail whose next epoch must use the recovered winners.
    let spec = fixture("chain-spec.polkajam.json");
    let spec = JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).unwrap();
    let [incomplete_tail, before_tail, tail] = checkpoint_cases(spec.params());
    let epoch_len = usize::try_from(spec.params().epoch_len).unwrap();
    for (anchor_index, tip_index) in [
        (incomplete_tail, incomplete_tail + 1),
        (before_tail, tail + 1),
        (tail, tail + epoch_len),
    ] {
        let executor = Arc::new(smol::Executor::new());
        let scenario_executor = executor.clone();
        let scenario = executor.spawn(async move {
            let (platform, raw, headers) = event_driven_fixture(&scenario_executor, 1);
            let mut spec: Value = serde_json::from_str(&raw).unwrap();
            spec["checkpoint"] = checkpoint_fixture(anchor_index);
            let spec = spec.to_string();
            let parsed = JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap();
            let anchor = &headers[anchor_index];
            let anchor_hash = anchor.hash(parsed.params());
            let tip = &headers[tip_index];
            {
                let mut c = platform.0.lock().unwrap();
                c.responses.retain(|hash, _| headers[..=tip_index].iter().any(|h| h.hash(parsed.params()) == *hash));
                c.handshake = framed(Handshake {
                    final_: Final {
                        hash: parsed.genesis_header().hash(parsed.params()),
                        slot: parsed.genesis_header().slot,
                    },
                    leaves: vec![Final { hash: tip.hash(parsed.params()), slot: tip.slot }],
                }.encode());
            }
            let mut client = Client::new(platform.clone());
            let added = client.add_chain(AddChainConfig {
                specification: &spec,
                user_data: (),
                database_content: "",
                potential_relay_chains: core::iter::empty(),
                json_rpc: AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
                    max_subscriptions: 2,
                },
                statement_protocol_config: None,
            }).unwrap();
            let mut responses = added.json_rpc_responses.unwrap();
            client.json_rpc_request(r#"{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[false]}"#, added.chain_id).unwrap();
            let id = response(&mut responses).await["result"].as_str().unwrap().to_owned();
            let initialized = response(&mut responses).await;
            assert_eq!(initialized["params"]["subscription"], id);
            assert_eq!(initialized["params"]["result"], json!({
                "event":"initialized",
                "finalizedBlockHashes":[alloc::format!("0x{}", hex::encode(anchor_hash))],
            }));
            assert_eq!(response(&mut responses).await["params"]["result"], json!({
                "event":"bestBlockChanged",
                "bestBlockHash":alloc::format!("0x{}", hex::encode(anchor_hash)),
            }));
            for header in &headers[anchor_index + 1..=tip_index] {
                let hash = alloc::format!("0x{}", hex::encode(header.hash(parsed.params())));
                let block = response(&mut responses).await;
                assert_eq!(block["params"]["subscription"], id);
                assert_eq!(block["params"]["result"]["event"], "newBlock");
                assert_eq!(block["params"]["result"]["blockHash"], hash);
                assert_eq!(block["params"]["result"]["parentBlockHash"], alloc::format!("0x{}", hex::encode(header.parent)));
                assert_eq!(response(&mut responses).await["params"]["result"], json!({
                    "event":"bestBlockChanged", "bestBlockHash":hash,
                }));
            }
            // The fixed checkpoint and every descendant remain pinned. Requests
            // also serve as barriers against any extra stop/finalized events.
            for (request_id, header) in headers[anchor_index..=tip_index].iter().enumerate() {
                let request_id = request_id + 10;
                client.json_rpc_request(json!({
                    "jsonrpc":"2.0", "id":request_id, "method":"chainHead_v1_header",
                    "params":[id, alloc::format!("0x{}", hex::encode(header.hash(parsed.params())))],
                }).to_string(), added.chain_id).unwrap();
                let reply = response(&mut responses).await;
                assert_eq!(reply["id"], request_id);
                assert_eq!(reply["result"], alloc::format!("0x{}", hex::encode(header.encode(parsed.params()))));
            }
            until(|| platform.0.lock().unwrap().io.pending_waits != 0).await;
            {
                let c = platform.0.lock().unwrap();
                assert_eq!(c.attempts, 1, "older peer finality must not disconnect a useful peer");
                assert_eq!(c.io.live_connections, 1);
                assert_eq!(c.requests.iter().map(|r| r.hash).collect::<Vec<_>>(),
                    {
                        let mut index = anchor_index;
                        c.requests.iter().map(|request| {
                            let hash = headers[index].hash(parsed.params());
                            index += usize::try_from(request.max_blocks).unwrap();
                            hash
                        }).collect::<Vec<_>>()
                    });
                assert!(c.requests.iter().all(|r| (1..=64).contains(&r.max_blocks) && r.direction == Direction::AscendingExclusive));
            }
            let () = client.remove_chain(added.chain_id);
            assert!(responses.next().await.is_none());
            until(|| {
                let c = platform.0.lock().unwrap();
                c.io.live_tasks == 0 && c.io.live_connections == 0 && c.io.live_streams == 0
            }).await;
        });
        smol::block_on(executor.run(scenario));
    }
}

#[test]
fn adaptive_batch_limit_stays_lowered_after_oversize_reconnect() {
    let mut size = FetchSize::default();
    for expected in [2, 4, 8, 16, 32, 64, 64] {
        size.received(FRAME_BYTES / 2 - 1);
        assert_eq!(size.count, expected);
    }
    size.oversized();
    assert_eq!(size.count, 32);
    size.received(100);
    assert_eq!(size.count, 32);
    for _ in 0..10 {
        size.oversized();
    }
    assert_eq!(size.count, 1);
    size.received(100);
    assert_eq!(size.count, 1);
}
