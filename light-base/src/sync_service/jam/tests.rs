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
    let state = LightState::from_parts(
        [[0; 32]; 4],
        vec![([0; 32], [0; 32]); 6],
        vec![([0; 32], [0; 32]); 6],
        SealingSequence::Keys(vec![[0; 32]]),
        None,
        0,
    );
    State {
        reads: StateReads::default(),
        #[cfg(test)]
        test_verifier: None,
        tree: HeaderTree::new(
            params.clone(),
            verified_genesis(&params, header, state),
            tree::Config {
                max_blocks: NonZeroUsize::new(4).unwrap(),
                max_bytes: usize::MAX,
                max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
            },
        )
        .unwrap(),
        authorities: AuthoritySet::from_checkpoint(&params, 0, vec![[0; 32]; 6], vec![[0; 32]; 6])
            .unwrap(),
        max_blocks: 4,
        proof_owner: None,
        proof_attempts: Vec::new(),
        tree_config: tree::Config {
            max_blocks: NonZeroUsize::new(4).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: NonZeroUsize::new(8).unwrap(),
        },
        warp_owner: None,
        warp_revision: 0,
        root_refusals: None,
        peer_count: 2,
        params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: 4096,
    }
}

#[test]
fn state_reads_provenance_retry_and_transient() {
    smol::block_on(async {
        for trust in [Trust::Finalized, Trust::Authenticated] {
            let mut reads = StateReads::default();
            let key = trie::state_key(8);
            let mut node = [0; 64];
            node[0] = 0x81;
            node[1..32].copy_from_slice(&key);
            node[32] = 7;
            let root = smoldot::jam::crypto::blake2b_256(&node);
            let read = StateRead {
                root_header: Some([3; 32]),
                at: [9; 32],
                root,
                trust,
                request: StateRequest {
                    block: [9; 32],
                    start: key,
                    end: key,
                    max_size: 4000,
                },
            };
            let result = reads.start(read.clone()).unwrap();
            assert!(reads.start(read.clone()).is_err());
            assert!(reads.reserve(0).is_some());
            assert!(reads.reserve(1).is_none());
            reads.release(0, true);
            assert!(reads.reserve(0).is_some());
            let bad = StateResponse {
                nodes: vec![node],
                entries: vec![(key, vec![8])],
            };
            assert!(reads.received(0, &bad).is_err());
            assert!(reads.reserve(0).is_none());
            assert!(reads.reserve(1).is_some());
            let good = StateResponse {
                nodes: vec![node],
                entries: vec![(key, vec![7])],
            };
            reads.received(1, &good).unwrap();
            let result = result.await.unwrap().unwrap();
            assert_eq!(result.root_header, read.root_header);
            assert_eq!(
                (result.at, result.root, result.trust),
                (read.at, root, trust)
            );
            assert_eq!(result.range.entries, good.entries);
        }
        let mut reads = StateReads::default();
        let req = StateRequest {
            block: [9; 32],
            start: [0; 31],
            end: [0; 31],
            max_size: 1,
        };
        let _rx = reads
            .start(StateRead {
                root_header: None,
                at: req.block,
                root: [0; 32],
                trust: Trust::Finalized,
                request: req,
            })
            .unwrap();
        assert!(reads.reserve(0).is_some());
        reads.release(0, false); // NoData: another peer, not the refusing peer.
        assert!(reads.reserve(0).is_none());
        assert!(reads.reserve(1).is_some());
        assert_eq!(
            classify_reset("jamnp-stream-reset:6 missing"),
            net::RequestError::NoData
        );
        assert_eq!(
            classify_reset("jamnp-stream-reset:3 busy"),
            net::RequestError::Transient
        );
        assert_eq!(classify_reset("error 6"), net::RequestError::Rejected);
    });
}

#[test]
fn state_read_exhaustion_frees_slot() {
    smol::block_on(async {
        for peers in 0..=2 {
            let mut reads = StateReads::new(peers);
            let read = StateRead {
                at: [0; 32],
                root: [0; 32],
                trust: Trust::Finalized,
                root_header: None,
                request: StateRequest {
                    block: [0; 32],
                    start: [0; 31],
                    end: [0; 31],
                    max_size: 1,
                },
            };
            let rx = reads.start(read.clone()).unwrap();
            for peer in 0..peers {
                assert!(reads.reserve(peer).is_some());
                reads.release(peer, false);
            }
            assert_eq!(rx.await.unwrap().unwrap_err(), StateReadError::Unavailable);
            assert!(reads.start(read).is_ok());
        }
    });
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
    let mut child = Header::decode(&state.params, &root.encoded).unwrap();
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
    state_responses: VecDeque<Result<Vec<u8>, &'static str>>,
    state_requests: Vec<Vec<u8>>,
    params: Option<Params>,
    reject_batch_above: Option<u32>,
    proofs: BTreeMap<Hash, Vec<u8>>,
    warps: BTreeMap<u32, Vec<u8>>,
    warp_requests: Vec<u32>,
    bad_warp_once: bool,
    warp_resets: VecDeque<&'static str>,
    proof_resets: VecDeque<&'static str>,
    block_resets: VecDeque<(Direction, &'static str)>,
    logs: Vec<String>,
    log_fields: Vec<(String, BTreeMap<String, String>)>,
    proof_requests: Vec<Hash>,
    preferred_child: Option<(Hash, Hash)>,
    no_blocks: usize,
    fork_announcement: Option<Vec<u8>>,
    join_announcement: Option<Vec<u8>>,
    announce_during_join: bool,
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
        fields: impl Iterator<Item = (&'a str, &'a dyn core::fmt::Display)>,
    ) {
        if message == "jam-block-request-queued" || message == "jam-warp-request-queued" {
            self.0.lock().unwrap().queued = true;
        }
        self.0.lock().unwrap().io.logs.push(message.into());
        self.0.lock().unwrap().io.log_fields.push((
            message.into(),
            fields
                .map(|(key, value)| (key.into(), value.to_string()))
                .collect(),
        ));
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
            connection.control.lock().unwrap().io.live_streams += 3;
            for _ in 0..3 {
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
        if stream.ce
            && !stream.response_started
            && stream.rw.write_bytes_queueable.is_none()
            && stream.outgoing[0] == 129
        {
            let mut c = stream.control.lock().unwrap();
            c.io.state_requests.push(stream.outgoing[5..].to_vec());
            stream.incoming =
                c.io.state_responses
                    .pop_front()
                    .expect("unscripted state read")?
                    .into();
            stream.response_started = true;
        }
        if stream.ce
            && !stream.response_started
            && stream.rw.write_bytes_queueable.is_none()
            && stream.outgoing[0] == 130
        {
            let hash: Hash = stream.outgoing[5..37].try_into().unwrap();
            let mut c = stream.control.lock().unwrap();
            c.io.proof_requests.push(hash);
            if let Some(reason) = c.io.proof_resets.pop_front() {
                return Err(reason);
            }
            let Some(response) = c.io.proofs.get(&hash).cloned() else {
                return Err("jamnp-stream-reset:6 no justification");
            };
            stream.incoming = response.into();
            stream.response_started = true;
        }
        if stream.ce
            && !stream.response_started
            && stream.rw.write_bytes_queueable.is_none()
            && stream.outgoing[0] == 153
        {
            let start = u32::from_le_bytes(stream.outgoing[5..9].try_into().unwrap());
            let mut c = stream.control.lock().unwrap();
            c.io.warp_requests.push(start);
            if let Some(reason) = c.io.warp_resets.pop_front() {
                return Err(reason);
            }
            let Some(mut response) = c.io.warps.get(&start).cloned() else {
                return Err("jamnp-stream-reset:6 no warp fragments");
            };
            if c.io.bad_warp_once {
                c.io.bad_warp_once = false;
                response[5] ^= 1; // Authenticated header parent, not the frame/count.
            }
            stream.incoming = response.into();
            stream.response_started = true;
        }
        if stream.ce && !stream.response_started && stream.rw.write_bytes_queueable.is_none() {
            assert_eq!(stream.outgoing[0], 128);
            let request = BlockRequest::decode(&stream.outgoing[5..]).unwrap();
            assert!((1..=64).contains(&request.max_blocks));
            let mut control = stream.control.lock().unwrap();
            if control
                .io
                .block_resets
                .front()
                .is_some_and(|(direction, _)| *direction == request.direction)
            {
                let (_, reason) = control.io.block_resets.pop_front().unwrap();
                control.requests.push(request);
                return Err(reason);
            }
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
                return Err("jamnp-stream-reset:6 no block");
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
            if (c
                .requests
                .iter()
                .any(|r| r.direction == Direction::AscendingExclusive)
                || (c.io.announce_during_join && !c.io.state_requests.is_empty()))
                && let Some(frame) = c.io.join_announcement.take()
            {
                stream.incoming.extend(frame);
            }
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
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
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
fn proof_work_includes_witnesses_beyond_a_small_retained_tree() {
    smol::block_on(async {
        use smoldot::{
            identity::keystore::{KeyNamespace, Keystore},
            jam::codec,
        };
        let mut state = root_state();
        let keys = Keystore::new(None, [43; 32]).await.unwrap();
        let public = keys
            .generate_ed25519(KeyNamespace::Grandpa, false)
            .await
            .unwrap();
        state.authorities =
            AuthoritySet::from_checkpoint(&state.params, 0, vec![public; 6], vec![public; 6])
                .unwrap();
        let mut block = state.tree.finalized().clone();
        let root = block.hash;
        let mut header = Header::decode(&state.params, &block.encoded).unwrap();
        header.parent = root;
        header.slot = 1;
        block.parent = root;
        block.encoded = header.encode(&state.params);
        block.slot = 1;
        block.hash = header.hash(&state.params);
        let target = block.hash;
        state.tree.insert_verified(root, block.clone()).unwrap();
        let mut witnesses = Vec::new();
        let mut previous = target;
        for slot in 2u32..=26 {
            header.parent = previous;
            header.slot = slot;
            previous = header.hash(&state.params);
            witnesses.push(header.clone());
        }
        assert!(state.proof_limits().max_ancestry_headers >= witnesses.len());
        assert!(state.proof_limits().max_ancestry_steps >= witnesses.len());
        // Every witness carries the same prior state root: the walk reaches the
        // target under it, so the commit must sign it as the target's root.
        let root = header.prior_state_root;
        let mut payload = b"jam_grandpa_vote".to_vec();
        payload.push(1);
        payload.extend(previous);
        payload.extend(root);
        payload.extend(26u32.to_le_bytes());
        payload.extend(1u64.to_le_bytes());
        payload.extend(0u32.to_le_bytes());
        let signature = keys
            .sign(KeyNamespace::Grandpa, &public, &payload)
            .await
            .unwrap();
        let mut proof = 1u64.to_le_bytes().to_vec();
        proof.extend(0u32.to_le_bytes());
        proof.extend(target);
        proof.extend(root);
        proof.extend(1u32.to_le_bytes());
        proof.extend(codec::encode_natural(1));
        proof.extend(previous);
        proof.extend(root);
        proof.extend(26u32.to_le_bytes());
        proof.extend(signature);
        proof.extend(public);
        proof.extend(codec::encode_natural(witnesses.len().try_into().unwrap()));
        for header in witnesses {
            proof.extend(header.encode(&state.params));
        }
        state.finalize(target, &proof).unwrap();
        assert_eq!(state.tree.finalized().hash, target);
    });
}

#[test]
fn conservative_full_network_and_oversized_parameter_budgets() {
    let mut params = root_state().params;
    params.epoch_len = 600;
    params.max_validators = 1023;
    let (header, limits) = memory_limits(&params).unwrap();
    let state = 600 * 160 + 1023 * 256 + 2048;
    assert!(limits.max_blocks.get() >= 2048);
    assert!(limits.max_bytes * 2 + header + state <= TREE_BYTES);
    let epoch = smoldot::jam::state::EpochState {
        active: vec![([0; 32], [0; 32]); 1023],
        pending: vec![([0; 32], [0; 32]); 1023],
        sealing: SealingSequence::Keys(vec![[0; 32]; 600]),
        history: [[0; 32]; 3],
    };
    let record =
        core::mem::size_of_val(&epoch) + 2 * core::mem::size_of::<usize>() + 2046 * 64 + 600 * 32;
    assert!(2048 * HeaderTree::node_overhead() + record <= limits.max_bytes);
    let anchor = Header::decode(&params, &root_state().tree.finalized().encoded).unwrap();
    let root = verified_genesis(
        &params,
        anchor.clone(),
        LightState::from_parts(
            [[0; 32]; 4],
            epoch.active,
            epoch.pending,
            epoch.sealing,
            None,
            0,
        ),
    );
    let mut tree = HeaderTree::new(params.clone(), root.clone(), limits).unwrap();
    for i in 0u32..2048 {
        let mut block = root.clone();
        let mut header = anchor.clone();
        header.parent = root.hash;
        header.slot = 1;
        header.extrinsic_hash[..4].copy_from_slice(&i.to_le_bytes());
        block.parent = header.parent;
        block.encoded = header.encode(&params);
        block.slot = 1;
        block.hash = header.hash(&params);
        tree.insert_verified(root.hash, block).unwrap();
    }
    assert_eq!(tree.len(), 2049);
    assert_eq!(tree.epoch_records(), 1);
    assert!(tree.retained_bytes() <= limits.max_bytes);
    std::println!(
        "D13 full retention: 2048 markless + root, bytes={}, record={record}, max_bytes={}",
        tree.retained_bytes(),
        limits.max_bytes
    );
    std::println!(
        "full-network budget: header={header}, state={state}, retained blocks={}, tree/transient ceiling={TREE_BYTES}",
        limits.max_blocks.get()
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
                authorities: state.authorities,
                max_blocks: 4,
                tree_config: state.tree_config,
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
        reads: StateReads::default(),
        #[cfg(test)]
        test_verifier: None,
        tree: config.tree,
        params: config.params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: config.header_bytes,
        authorities: config.authorities,
        max_blocks: config.max_blocks,
        proof_owner: None,
        proof_attempts: Vec::new(),
        tree_config: config.tree_config,
        warp_owner: None,
        warp_revision: 0,
        root_refusals: None,
        peer_count: config.peers.len(),
    };
    for index in 0..36 {
        let header = Header::decode(
            &state.params,
            &bytes(&fixture(&alloc::format!("headers/{index:04}.json"))["header_hex"]),
        )
        .unwrap();
        state.insert(header, 1_800_000_000).unwrap();
    }
    let measured = state.tree.retained_bytes();
    std::println!(
        "37 authenticated fixture nodes: {measured} accounted retained bytes; tree+transient ceiling={TREE_BYTES}"
    );
    assert!(measured * 2 < TREE_BYTES);
    let anchor = state.tree.finalized().clone();
    let mut full = State {
        reads: StateReads::default(),
        #[cfg(test)]
        test_verifier: None,
        tree: HeaderTree::new(
            state.params.clone(),
            anchor.clone(),
            tree::Config {
                max_blocks: core::num::NonZeroUsize::new(2).unwrap(),
                max_bytes: usize::MAX,
                max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
            },
        )
        .unwrap(),
        params: state.params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: state.header_bytes,
        authorities: state.authorities,
        max_blocks: 2,
        proof_owner: None,
        proof_attempts: Vec::new(),
        tree_config: state.tree_config,
        warp_owner: None,
        warp_revision: 0,
        root_refusals: None,
        peer_count: 2,
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
        assert_eq!(
            Header::decode(&config.params, &config.tree.finalized().encoded).unwrap(),
            checkpoint.header
        );
        assert_eq!(config.tree.len(), 1);
        let epoch_len = usize::try_from(parsed.params().epoch_len).unwrap();
        match case {
            0 => {
                assert!(
                    raw_state.slot % parsed.params().epoch_len >= parsed.params().epoch_tail_start
                );
                assert!(raw_state.safrole.ticket_accumulator.len() < epoch_len);
                assert!(
                    config
                        .tree
                        .finalized()
                        .post_state
                        .pending_tickets()
                        .is_none()
                );
            }
            1 => {
                assert!(
                    raw_state.slot % parsed.params().epoch_len < parsed.params().epoch_tail_start
                );
                assert_eq!(raw_state.safrole.ticket_accumulator.len(), epoch_len);
                assert!(
                    config
                        .tree
                        .finalized()
                        .post_state
                        .pending_tickets()
                        .is_none()
                );
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
                    config.tree.finalized().post_state.pending_tickets(),
                    Some(winners.as_slice())
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
    // These header-sync fixtures do not claim finality. Supply explicit trusted
    // GRANDPA state rather than deriving it from their slots.
    let keys = vec![hex::encode([1; 32]); 6];
    json!({"finality":{"set_id":0,"current":keys,"next":keys}, "header":checkpoint["header_hex"], "state":{"safrole":item(4),"entropy":item(6),"active_validators":item(8),"slot":item(11)}})
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

fn rpc_large_snapshot_blocks() -> Vec<BlockNotification> {
    let mut parent_hash = blake2b_256(&[0]);
    (1u32..=600)
        .map(|number| {
            let block = BlockNotification {
                is_new_best: number == 600,
                scale_encoded_header: number.to_le_bytes().to_vec(),
                parent_hash,
            };
            parent_hash = blake2b_256(&block.scale_encoded_header);
            block
        })
        .collect()
}

#[test]
fn jam_rpc_large_snapshot_initializes_then_excess_finality_stops_follow() {
    smol::block_on(async {
        let blocks = rpc_large_snapshot_blocks();
        let best = &blocks.last().unwrap().scale_encoded_header;
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, best).await;
        for bytes in core::iter::once(&root).chain(blocks.iter().map(|b| &b.scale_encoded_header)) {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "chainHead_v1_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await["result"],
                alloc::format!("0x{}", hex::encode(bytes))
            );
        }
        notifications
            .try_send(Notification::Finalized {
                finalized_blocks_hashes: blocks
                    .iter()
                    .map(|block| blake2b_256(&block.scale_encoded_header))
                    .collect(),
                best_block_hash_if_changed: Some(blake2b_256(best)),
                pruned_blocks: Vec::new(),
            })
            .unwrap();
        // Rejection must emit only stop, not bestBlockChanged or finalized first.
        let stopped = rpc_message(&frontend).await;
        assert_eq!(stopped["params"]["subscription"], id);
        assert_eq!(stopped["params"]["result"], json!({"event":"stop"}));
        for bytes in [&root, best] {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "chainHead_v1_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await
                .get("result"),
                Some(&Value::Null)
            );
        }
    });
}

#[test]
fn jam_rpc_unpin_refunds_finalized_budget_for_later_finality() {
    smol::block_on(async {
        let blocks = rpc_large_snapshot_blocks();
        let best = &blocks.last().unwrap().scale_encoded_header;
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, best).await;
        for (index, batch) in blocks.chunks(300).enumerate() {
            notifications
                .try_send(Notification::Finalized {
                    finalized_blocks_hashes: batch
                        .iter()
                        .map(|block| blake2b_256(&block.scale_encoded_header))
                        .collect(),
                    best_block_hash_if_changed: None,
                    pruned_blocks: Vec::new(),
                })
                .unwrap();
            let finalized = rpc_message(&frontend).await;
            assert_eq!(finalized["params"]["subscription"], id);
            assert_eq!(
                finalized["params"]["result"],
                json!({
                    "event":"finalized",
                    "finalizedBlockHashes":batch.iter().map(|b| rpc_hash(&b.scale_encoded_header)).collect::<Vec<_>>(),
                    "prunedBlockHashes":[],
                })
            );
            if index == 0 {
                let unpinned: Vec<_> = blocks[..100]
                    .iter()
                    .map(|block| rpc_hash(&block.scale_encoded_header))
                    .collect();
                assert_eq!(
                    rpc_call(&frontend, "chainHead_v1_unpin", json!([id, unpinned]))
                        .await
                        .get("result"),
                    Some(&Value::Null)
                );
                for hash in unpinned {
                    assert_eq!(
                        rpc_call(&frontend, "chainHead_v1_header", json!([id, hash])).await["error"]
                            ["code"],
                        -32801
                    );
                }
            }
        }
        // Without the 100 refunds, the second charge of 300 would stop this follow.
        for bytes in core::iter::once(&root).chain(
            blocks[100..]
                .iter()
                .map(|block| &block.scale_encoded_header),
        ) {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "chainHead_v1_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await["result"],
                alloc::format!("0x{}", hex::encode(bytes))
            );
        }
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
#[ignore = "requires sibling smoldot library fixture in a source checkout"]
fn external_captured_finality_requests_are_deduplicated_and_notifications_follow_verification() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../lib/src/jam/finality/fixtures/polkajam-grandpa.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let spec = JamChainSpec::from_json_bytes(fixture["spec"].to_string().as_bytes()).unwrap();
    let config = Config::from_spec(&spec).unwrap();
    let mut state = State {
        reads: StateReads::default(),
        #[cfg(test)]
        test_verifier: None,
        tree: config.tree,
        params: config.params,
        subscribers: Vec::new(),
        stopped: false,
        header_bytes: config.header_bytes,
        authorities: config.authorities,
        max_blocks: config.max_blocks,
        proof_owner: None,
        proof_attempts: Vec::new(),
        tree_config: config.tree_config,
        warp_owner: None,
        warp_revision: 0,
        root_refusals: None,
        peer_count: config.peers.len(),
    };
    for encoded in fixture["headers"].as_array().unwrap() {
        let header = Header::decode(
            &state.params,
            &hex::decode(encoded.as_str().unwrap().trim_start_matches("0x")).unwrap(),
        )
        .unwrap();
        state.insert(header, 1_900_000_000).unwrap();
    }
    let snapshot = state.subscribe(16, false);
    let advertised = Final {
        hash: state.tree.best().hash,
        slot: state.tree.best().slot,
    };
    let first_target = state.reserve_proof(0, &advertised).unwrap();
    assert_eq!(
        state.reserve_proof(1, &advertised),
        None,
        "deduplicate across peers"
    );
    state.proof_owner = None; // First peer failed or timed out.
    assert_eq!(
        state.reserve_proof(0, &advertised),
        None,
        "do not repeat a rejected target on the same peer"
    );
    assert_eq!(state.reserve_proof(1, &advertised), Some(first_target));
    let root = state.tree.finalized().hash;
    let set_id = state.authorities.set_id();
    assert!(state.finalize(first_target, &[0xff]).is_err());
    assert_eq!(state.tree.finalized().hash, root);
    assert_eq!(state.authorities.set_id(), set_id);
    assert!(snapshot.new_blocks.try_recv().is_err());
    for encoded in fixture["justifications"].as_array().unwrap() {
        let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
        let proof = Justification::decode(&state.params, &bytes, state.proof_limits()).unwrap();
        state.finalize(proof.target().hash, &bytes).unwrap();
        let notification = snapshot.new_blocks.try_recv().unwrap();
        assert!(
            matches!(notification, Notification::Finalized { ref finalized_blocks_hashes, .. }
            if finalized_blocks_hashes.last() == Some(&state.tree.finalized().hash))
        );
    }
    assert_eq!(state.authorities.set_id(), 3);
    assert!(state.tree.len() <= 2);
    assert!(!snapshot.new_blocks.is_closed());
}

fn synthetic_driver(blocks: usize, capacity: usize) -> (FakePlatform, Config, Vec<Header>) {
    let corpus = fixture("d15/synthetic.json");
    let (platform, boot_spec, _, _) = fixture_setup();
    let mut spec = corpus["spec"].clone();
    spec["bootnodes"] = serde_json::from_str::<Value>(&boot_spec).unwrap()["bootnodes"].clone();
    let spec = JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).unwrap();
    let mut config = Config::from_spec(&spec).unwrap();
    config.tree = HeaderTree::new(
        config.params.clone(),
        config.tree.finalized().clone(),
        tree::Config {
            max_blocks: NonZeroUsize::new(capacity).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: core::num::NonZeroUsize::new(8).unwrap(),
        },
    )
    .unwrap();
    config.max_blocks = capacity;
    let headers: Vec<_> = corpus["headers"]
        .as_array()
        .unwrap()
        .iter()
        .take(blocks)
        .map(|raw| Header::decode(&config.params, &bytes(raw)).unwrap())
        .collect();
    let tip = headers.last().unwrap();
    {
        let mut c = platform.0.lock().unwrap();
        c.responses.clear();
        c.io.params = Some(config.params.clone());
        for header in &headers {
            let mut block = header.encode(&config.params);
            block.extend([0; 7]); // Five components; disputes has three lists.
            c.responses
                .insert(header.hash(&config.params), framed(block));
        }
        c.handshake = framed(
            Handshake {
                final_: Final {
                    hash: tip.hash(&config.params),
                    slot: tip.slot,
                },
                leaves: vec![],
            }
            .encode(),
        );
        for (hash, proof) in corpus["proofs"].as_object().unwrap() {
            c.io.proofs.insert(
                hex::decode(hash).unwrap().try_into().unwrap(),
                framed(bytes(proof)),
            );
        }
    }
    (platform, config, headers)
}

#[test]
fn captured_join_reanchors_at_finalized_head_and_verifies_child() {
    smol::block_on(async {
        let (mut s, w) = captured_join().await;
        let target = w.head.clone().unwrap();
        let old = s.subscribe(16, false);
        s.apply_warp(0, w).unwrap();
        assert!(old.new_blocks.is_closed());
        assert_eq!(s.tree.finalized().hash, target.hash(&s.params));
        let follow = s.subscribe(16, false);
        assert_eq!(
            follow.finalized_block_scale_encoded_header,
            target.encode(&s.params)
        );
        let child =
            Header::decode(&s.params, &bytes(&join_vector()["child"]["header_hex"])).unwrap();
        s.insert(child.clone(), 1_900_000_000).unwrap();
        assert_eq!(s.tree.best().hash, child.hash(&s.params));
        assert!(matches!(
            follow.new_blocks.recv().await.unwrap(),
            Notification::Block(_)
        ));
    });
}

#[test]
#[ignore = "requires external D14 signed synthetic corpus"]
fn external_warp_paginates_32_then_short_batch_or_no_data() {
    smol::block_on(async {
        for no_data in [false, true] {
            let (platform, config, headers) = synthetic_driver(600, 32);
            let params = config.params.clone();
            let mut fragments = Vec::new();
            {
                let mut c = platform.0.lock().unwrap();
                for h in headers.iter().filter(|h| h.epoch_mark.is_some()) {
                    let mut fragment = h.encode(&params);
                    fragment.extend_from_slice(&c.io.proofs[&h.hash(&params)][4..]);
                    fragments.push(fragment);
                }
                assert!(fragments.len() > 32);
                for (index, batch) in fragments.chunks(32).enumerate() {
                    if no_data && index == 1 {
                        break;
                    }
                    let mut payload =
                        smoldot::jam::codec::encode_natural(u64::try_from(batch.len()).unwrap());
                    for fragment in batch {
                        payload.extend(fragment);
                    }
                    c.io.warps
                        .insert(u32::try_from(index * 32).unwrap(), framed(payload));
                }
                // This corpus has no state proofs: stop specifically at the F
                // join request. The committed join corpus covers completion.
                c.io.block_resets
                    .push_back((Direction::DescendingInclusive, "join unavailable"));
            }
            let advertised = Handshake::decode(&platform.0.lock().unwrap().handshake[4..], 8)
                .unwrap()
                .final_;
            let state = driver_state(config);
            let original = state.lock().await.tree.finalized().clone();
            future::or(d7_drive(&platform, &params, &state, 0, 64), async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("pagination did not reach finalized-state join");
            })
            .await;
            assert_eq!(state.lock().await.tree.finalized(), &original);
            let c = platform.0.lock().unwrap();
            assert_eq!(c.io.warp_requests, vec![0, 32]);
            assert_eq!(c.requests.len(), 1);
            assert_eq!(c.requests[0].hash, advertised.hash);
            assert_eq!(c.requests[0].direction, Direction::DescendingInclusive);
            assert_eq!(c.requests[0].max_blocks, 1);
            drop(c);
            if no_data {
                assert_reset_log(
                    &platform,
                    "jamnp-stream-reset:6 no warp fragments",
                    "NoData",
                );
            }
        }
    });
}

/// Assembled from D1's live CE130 proofs and headers, NOT a live CE153 capture.
fn d7_setup(pruned: bool) -> (FakePlatform, Config, Vec<Header>, Header) {
    if pruned {
        return join_setup();
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../lib/src/jam/finality/fixtures/polkajam-grandpa.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let spec = JamChainSpec::from_json_bytes(fixture["spec"].to_string().as_bytes()).unwrap();
    let config = Config::from_spec(&spec).unwrap();
    let params = &config.params;
    let headers: Vec<_> = fixture["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| Header::decode(params, &bytes(h)).unwrap())
        .collect();
    let limits = finality::Limits {
        max_bytes: FRAME_BYTES,
        max_ancestry_headers: 64,
        max_ancestry_steps: 4096,
    };
    let mut fragments = Vec::new();
    let mut proofs = BTreeMap::new();
    for value in fixture["justifications"].as_array().unwrap() {
        let raw = bytes(value);
        let proof = Justification::decode(params, &raw, limits).unwrap();
        let header = headers
            .iter()
            .find(|h| h.hash(params) == proof.target().hash)
            .unwrap();
        if header.epoch_mark.is_some() {
            fragments.push((header.clone(), raw.clone()));
        }
        proofs.insert(proof.target().hash, framed(raw));
    }
    assert_eq!(fragments.len(), 3);
    let target = fragments.last().unwrap().0.clone();
    let mut response = smoldot::jam::codec::encode_natural(u64::try_from(fragments.len()).unwrap());
    for (header, proof) in fragments {
        response.extend(header.encode(params));
        response.extend(proof);
    }
    let mut responses = BTreeMap::new();
    for header in &headers {
        let mut block = header.encode(params);
        block.extend([0; 7]);
        responses.insert(header.hash(params), framed(block));
    }
    let tip = &headers[headers.len() - 2]; // Last fixture header has no captured proof.
    let platform = FakePlatform(Arc::new(Mutex::new(Control {
        handshake: framed(
            Handshake {
                final_: Final {
                    hash: tip.hash(params),
                    slot: tip.slot,
                },
                leaves: vec![],
            }
            .encode(),
        ),
        responses,
        requests: vec![],
        attempts: 0,
        fail_first: false,
        supported: true,
        pins: vec![],
        disconnect: false,
        starve: false,
        queued: false,
        clock_shift: Duration::ZERO,
        io: IoState {
            params: Some(params.clone()),
            proofs,
            warps: BTreeMap::from([(0, framed(response))]),
            ..IoState::default()
        },
    })));
    (platform, config, headers, target)
}

fn join_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../lib/src/jam/trie/fixtures/polkajam-join.json"
    ))
    .unwrap()
}

fn join_exchange(vector: &Value, name: &str) -> Vec<u8> {
    bytes(
        &vector["exchanges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap()["response_frame_hex"],
    )
}

async fn captured_join() -> (State, Warp) {
    let vector = join_vector();
    let spec = JamChainSpec::from_json_bytes(vector["spec"].to_string().as_bytes()).unwrap();
    let state = driver_state(Config::from_spec(&spec).unwrap());
    let mut s = Arc::try_unwrap(state).ok().unwrap().into_inner();
    let head = join_exchange(&vector, "join-head");
    let blocks =
        smoldot::jam::types::Block::decode_sequence(&s.params, &head[4..], FRAME_BYTES, 1).unwrap();
    let proof = join_exchange(&vector, "join-finality");
    let set_id = Justification::decode(&s.params, &proof[4..], s.proof_limits())
        .unwrap()
        .set_id();
    // Capture records the fixed dev set; this replay starts at a staged set,
    // independently of the scripted fragment-chain test below.
    s.authorities = AuthoritySet::from_checkpoint(
        &s.params,
        set_id,
        s.authorities.current().to_vec(),
        s.authorities.current().to_vec(),
    )
    .unwrap();
    let mut w = s.reserve_warp(0).unwrap();
    w.final_head = Some(Final {
        hash: blocks[0].header.hash(&s.params),
        slot: blocks[0].header.slot,
    });
    assert!(w.next_read().is_err());
    w.receive_headers(&s.params, blocks, s.header_bytes)
        .unwrap();
    assert!(w.next_read().is_err());
    w.authenticate(&s.params, &proof[4..], s.proof_limits())
        .unwrap();
    // The read is at F itself against the posterior root F's justification signs.
    let read = w.next_read().unwrap();
    assert_eq!(read.at, w.head.as_ref().unwrap().hash(&s.params));
    assert_eq!(hex::encode(read.root), vector["commit"]["state_root"]);
    assert_eq!(read.root_header, Some(read.at));
    assert_eq!(read.trust, Trust::Finalized);
    for name in ["join-c4", "join-c6", "join-c8", "join-c11"] {
        let frame = join_exchange(&vector, name);
        let n = usize::try_from(u32::from_le_bytes(frame[..4].try_into().unwrap())).unwrap();
        let response = StateResponse::decode(
            &frame[4..4 + n],
            &frame[8 + n..],
            &trie::ResponseLimits {
                max_nodes: 496,
                max_entries: 32768,
                max_value_bytes: FRAME_BYTES,
                max_total_bytes: FRAME_BYTES + 496 * 64,
            },
        )
        .unwrap();
        let rx = s.reads.start(w.next_read().unwrap()).unwrap();
        s.reads.reserve(0).unwrap();
        s.reads.received(0, &response).unwrap();
        w.items.extend(rx.await.unwrap().unwrap().range.entries);
    }
    (s, w)
}

// Real CE129 proofs and real sealed F/child, with explicitly assembled GRANDPA
// votes and three fragments signed by a scripted authority set (not a live warp).
// The scripted proof for F signs F's real posterior root, the child's prior root.
fn join_setup() -> (FakePlatform, Config, Vec<Header>, Header) {
    smol::block_on(async {
        use smoldot::identity::keystore::{KeyNamespace, Keystore};
        let (platform, mut config, old_headers, _) = d7_setup(false);
        let params = config.params.clone();
        let vector = join_vector();
        let head = join_exchange(&vector, "join-head");
        let blocks =
            smoldot::jam::types::Block::decode_sequence(&params, &head[4..], FRAME_BYTES, 1)
                .unwrap();
        let f = blocks[0].header.clone();
        let child = Header::decode(&params, &bytes(&vector["child"]["header_hex"])).unwrap();
        let keys = Keystore::new(None, [42; 32]).await.unwrap();
        let public = keys
            .generate_ed25519(KeyNamespace::Grandpa, false)
            .await
            .unwrap();
        config.authorities =
            AuthoritySet::from_checkpoint(&params, 0, vec![public; 6], vec![public; 6]).unwrap();
        let mut fragments = vec![3];
        for (set_id, original) in old_headers
            .iter()
            .filter(|h| h.epoch_mark.is_some())
            .enumerate()
        {
            let mut h = original.clone();
            for (_, ed) in &mut h.epoch_mark.as_mut().unwrap().validators {
                *ed = public;
            }
            fragments.extend(h.encode(&params));
            fragments.extend(
                scripted_join_proof(
                    &keys,
                    public,
                    &params,
                    &h,
                    [0; 32],
                    u32::try_from(set_id).unwrap(),
                )
                .await,
            );
        }
        let mut proofs = BTreeMap::new();
        // The child's own posterior root was not captured; its proof is scripted.
        for (h, root) in [(&f, child.prior_state_root), (&child, [0; 32])] {
            proofs.insert(
                h.hash(&params),
                framed(scripted_join_proof(&keys, public, &params, h, root, 3).await),
            );
        }
        let mut c = platform.0.lock().unwrap();
        c.responses.clear();
        for block in blocks {
            let mut body = block.header.encode(&params);
            body.extend(block.body);
            c.responses.insert(block.header.hash(&params), framed(body));
        }
        c.responses.insert(
            child.hash(&params),
            join_exchange(&vector, "finalized-child"),
        );
        c.handshake = framed(
            Handshake {
                final_: Final {
                    hash: f.hash(&params),
                    slot: f.slot,
                },
                leaves: vec![Final {
                    hash: child.hash(&params),
                    slot: child.slot,
                }],
            }
            .encode(),
        );
        c.io.proofs = proofs;
        c.io.join_announcement = Some(framed(
            smoldot::jam::types::Announcement {
                header: child.clone(),
                final_: Final {
                    hash: child.hash(&params),
                    slot: child.slot,
                },
            }
            .encode(&params),
        ));
        c.io.warps = BTreeMap::from([(0, framed(fragments))]);
        c.io.state_responses = ["join-c4", "join-c6", "join-c8", "join-c11"]
            .iter()
            .map(|name| Ok(join_exchange(&vector, name)))
            .collect();
        drop(c);
        (platform, config, vec![f.clone(), child], f)
    })
}

async fn scripted_join_proof(
    keys: &smoldot::identity::keystore::Keystore,
    public: [u8; 32],
    params: &Params,
    header: &Header,
    state_root: Hash,
    set_id: u32,
) -> Vec<u8> {
    use smoldot::identity::keystore::KeyNamespace;
    let hash = header.hash(params);
    let mut payload = b"jam_grandpa_vote".to_vec();
    payload.push(1);
    payload.extend(hash);
    payload.extend(state_root);
    payload.extend(header.slot.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(set_id.to_le_bytes());
    let signature = keys
        .sign(KeyNamespace::Grandpa, &public, &payload)
        .await
        .unwrap();
    let mut proof = 1u64.to_le_bytes().to_vec();
    proof.extend(set_id.to_le_bytes());
    proof.extend(hash);
    proof.extend(state_root);
    proof.extend(header.slot.to_le_bytes());
    proof.push(1);
    proof.extend(hash);
    proof.extend(state_root);
    proof.extend(header.slot.to_le_bytes());
    proof.extend(signature);
    proof.extend(public);
    proof.push(0);
    proof
}

async fn d7_drive(
    platform: &FakePlatform,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
    peer: usize,
    ceiling: u32,
) {
    let connected = platform
        .connect_multistream(MultiStreamAddress::WebTransport {
            ip: "127.0.0.1".parse().unwrap(),
            port: 4433,
            cert_hashes: Cow::Owned(vec![[1; 32]; 3]),
        })
        .await;
    drive(
        platform,
        "warp-scripted",
        params,
        peer,
        state,
        connected.connection,
        (&mut FetchSize { count: 1, ceiling }, &mut None),
    )
    .await;
}

#[test]
fn assembled_warp_reanchors_stops_followers_then_imports_and_finalizes() {
    smol::block_on(async {
        for full_range in [false, true] {
            let (platform, config, headers, target) = d7_setup(true);
            if full_range {
                let mut c = platform.0.lock().unwrap();
                c.io.state_responses =
                    [Ok(join_exchange(&join_vector(), "join-range-c4-c11"))].into();
                c.io.announce_during_join = true;
            }
            let params = config.params.clone();
            let state = driver_state(config);
            let old = state.lock().await.subscribe(16, false);
            let (mut oracle_state, oracle_join) = captured_join().await;
            oracle_state.apply_warp(0, oracle_join).unwrap();
            let oracle = oracle_state.tree.finalized().clone();
            future::or(
                async {
                    d7_drive(&platform, &params, &state, 0, 1).await;
                    panic!("warp driver disconnected");
                },
                future::or(
                    async {
                        loop {
                            if old.new_blocks.is_closed() {
                                break;
                            }
                            future::yield_now().await;
                        }
                        let follow = {
                            let mut s = state.lock().await;
                            assert_eq!(s.tree.finalized().hash, target.hash(&params));
                            assert_eq!(s.tree.finalized().post_state, oracle.post_state);
                            assert_eq!(s.authorities.set_id(), 3);
                            s.subscribe(16, false)
                        };
                        assert_eq!(
                            blake2b_256(&follow.finalized_block_scale_encoded_header),
                            target.hash(&params)
                        );
                        loop {
                            if matches!(
                                follow.new_blocks.recv().await.unwrap(),
                                Notification::Finalized { .. }
                            ) && state.lock().await.tree.finalized().slot > target.slot
                            {
                                break;
                            }
                        }
                    },
                    async {
                        smol::Timer::after(Duration::from_secs(10)).await;
                        panic!("warp timeout");
                    },
                ),
            )
            .await;
            let c = platform.0.lock().unwrap();
            assert!(c.io.logs.iter().any(|s| s == "jam-warp-applied"));
            assert!(c.io.log_fields.iter().any(|(message, fields)| {
                message == "jam-warp-join-selected"
                    && fields
                        .get("advertisement")
                        .is_some_and(|value| value == "1")
                    && fields
                        .get("slot")
                        .is_some_and(|value| value == &target.slot.to_string())
            }));
            assert_eq!(c.io.warp_requests, vec![0]);
            assert_eq!(c.io.state_requests.len(), if full_range { 1 } else { 4 });
            let descending: Vec<_> = c
                .requests
                .iter()
                .filter(|r| r.direction == Direction::DescendingInclusive)
                .collect();
            assert_eq!(descending.len(), 1);
            assert_eq!(descending[0].hash, target.hash(&params));
            assert_eq!(descending[0].max_blocks, 1, "the join fetches F alone");
            assert!(
                c.requests
                    .iter()
                    .any(|r| r.direction == Direction::DescendingInclusive)
            );
            let ascending: Vec<_> = c
                .requests
                .iter()
                .filter(|r| r.direction == Direction::AscendingExclusive)
                .collect();
            assert_eq!(ascending[0].hash, target.hash(&params));
            assert!(ascending.iter().all(|r| {
                headers
                    .iter()
                    .any(|h| h.hash(&params) == r.hash && h.slot >= target.slot)
            }));
        }
    });
}

#[test]
fn warp_no_data_keeps_anchor_and_ordinary_sync_works() {
    smol::block_on(async {
        let (platform, config, _, _) = d7_setup(false);
        platform.0.lock().unwrap().io.warps.clear();
        let params = config.params.clone();
        let root = config.tree.finalized().hash;
        let state = driver_state(config);
        let follow = state.lock().await.subscribe(16, false);
        future::or(
            async {
                d7_drive(&platform, &params, &state, 0, 64).await;
                panic!("ordinary sync disconnected");
            },
            future::or(
                async {
                    loop {
                        if matches!(
                            follow.new_blocks.recv().await.unwrap(),
                            Notification::Block(_)
                        ) {
                            break;
                        }
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("ordinary timeout");
                },
            ),
        )
        .await;
        let s = state.lock().await;
        assert_eq!(s.warp_revision, 0);
        assert!(!follow.new_blocks.is_closed());
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests[0].hash, root);
        assert_eq!(c.io.warp_requests, vec![0]);
        assert!(c.io.state_requests.is_empty());
        assert!(c.io.logs.iter().any(|s| s == "jam-warp-fragmentless"));
        assert!(!c.io.logs.iter().any(|s| s == "jam-warp-applied"));
        drop(c);
        assert_reset_log(
            &platform,
            "jamnp-stream-reset:6 no warp fragments",
            "NoData",
        );
    });
}

#[test]
fn tampered_warp_releases_reservation_and_other_peer_completes() {
    smol::block_on(async {
        let (platform, mut config, _, _) = d7_setup(true);
        platform.0.lock().unwrap().io.bad_warp_once = true;
        let peer = config.peers.remove(0);
        let params = config.params.clone();
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        future::or(
            future::or(
                peer_loop(&platform, "bad-peer", &peer, 0, &params, state.clone()),
                peer_loop(&platform, "good-peer", &peer, 1, &params, state.clone()),
            ),
            future::or(
                async {
                    loop {
                        if state.lock().await.warp_revision == 1 {
                            break;
                        }
                        future::yield_now().await;
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("failover timeout");
                },
            ),
        )
        .await;
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 2);
        assert!(c.io.logs.iter().any(|s| s == "jam-warp-rejected"));
        assert!(c.io.logs.iter().any(|s| s == "jam-warp-applied"));
    });
}

#[test]
fn ascending_no_data_at_available_root_waits_for_a_child_instead_of_stopping() {
    smol::block_on(async {
        let (platform, config, headers, _) = d7_setup(false);
        let params = config.params.clone();
        let root = config.tree.finalized().clone();
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.io.proofs.clear();
            c.responses.clear();
            let mut block = root.encoded.clone();
            block.extend([0; 7]);
            c.responses.insert(root.hash, framed(block));
            c.handshake = framed(
                Handshake {
                    final_: Final {
                        hash: root.hash,
                        slot: root.slot,
                    },
                    leaves: vec![Final {
                        hash: [99; 32],
                        slot: headers.last().unwrap().slot,
                    }],
                }
                .encode(),
            );
        }
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        assert!(state.lock().await.refuse_root(1, root.hash).is_ok());
        let follow = state.lock().await.subscribe(16, false);
        future::or(
            async {
                d7_drive(&platform, &params, &state, 0, 64).await;
                panic!("available root disconnected");
            },
            future::or(
                async {
                    loop {
                        if platform.0.lock().unwrap().requests.iter().any(|r| {
                            r.direction == Direction::DescendingInclusive && r.hash == root.hash
                        }) {
                            break;
                        }
                        future::yield_now().await;
                    }
                    smol::Timer::after(Duration::from_millis(20)).await;
                    assert!(!state.lock().await.stopped);
                    {
                        let mut c = platform.0.lock().unwrap();
                        c.io.no_blocks = 2;
                        c.io.fork_announcement = Some(framed(
                            smoldot::jam::types::Announcement {
                                header: headers[0].clone(),
                                final_: Final {
                                    hash: root.hash,
                                    slot: root.slot,
                                },
                            }
                            .encode(&params),
                        ));
                    }
                    assert!(matches!(
                        follow.new_blocks.recv().await.unwrap(),
                        Notification::Block(_)
                    ));
                    assert!(!state.lock().await.stopped);
                    assert!(state.lock().await.root_refusals.is_none());
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("root availability timeout");
                },
            ),
        )
        .await;
    });
}

#[test]
fn all_peers_refusing_warp_and_root_stop_without_reconnecting() {
    smol::block_on(async {
        let (platform, mut config, _, _) = d7_setup(false);
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.responses.clear();
        }
        let peer = config.peers.remove(0);
        let params = config.params.clone();
        let root = config.tree.finalized().hash;
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        let follow = state.lock().await.subscribe(16, false);
        future::or(
            future::or(
                peer_loop(&platform, "unserved-0", &peer, 0, &params, state.clone()),
                peer_loop(&platform, "unserved-1", &peer, 1, &params, state.clone()),
            ),
            future::or(
                async {
                    loop {
                        if state.lock().await.stopped {
                            break;
                        }
                        future::yield_now().await;
                    }
                    assert!(follow.new_blocks.is_closed());
                    assert_eq!(state.lock().await.tree.finalized().hash, root);
                    let attempts = platform.0.lock().unwrap().attempts;
                    smol::Timer::after(Duration::from_millis(1200)).await;
                    assert_eq!(platform.0.lock().unwrap().attempts, attempts);
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("terminal timeout");
                },
            ),
        )
        .await;
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 2);
        assert!(c.io.logs.iter().any(|s| s == "jam-anchor-unserved"));
        assert!(c.io.log_fields.iter().any(|(message, fields)| {
            message == "jam-anchor-unserved"
                && fields.get("reason").map(String::as_str) == Some("NoData")
        }));
    });
}

#[test]
fn reset_classifier_requires_the_exact_transport_code() {
    for code in 0..=8 {
        let expected = match code {
            6 => net::RequestError::NoData,
            2..=5 => net::RequestError::Transient,
            _ => net::RequestError::Rejected,
        };
        assert_eq!(
            classify_reset(&alloc::format!(
                "jamnp-stream-reset:{code} original message"
            )),
            expected
        );
    }
    assert_eq!(
        classify_reset("jamnp-stream-reset:6 "),
        net::RequestError::NoData
    );
    for message in [
        "no block",
        "streamErrorCode: 6",
        "jamnp-stream-reset:6",
        " jamnp-stream-reset:6 missing",
        "jamnp-stream-reset:60 missing",
        "jamnp-stream-reset:+6 missing",
        "jamnp-stream-reset:06 missing",
        "jamnp-stream-reset:6.0 missing",
        "jamnp-stream-reset:6\tmissing",
        "jamnp-stream-reset:999999999999999999999 missing",
    ] {
        assert_eq!(
            classify_reset(message),
            net::RequestError::Rejected,
            "{message}"
        );
    }
}

fn assert_reset_log(platform: &FakePlatform, raw: &str, reason: &str) {
    assert!(
        platform
            .0
            .lock()
            .unwrap()
            .io
            .log_fields
            .iter()
            .any(|(message, fields)| {
                message == "jam-stream-reset"
                    && fields.get("reason").map(String::as_str) == Some(reason)
                    && fields.get("message").map(String::as_str) == Some(raw)
            })
    );
}

#[test]
fn non_no_data_root_probes_reconnect_without_counting_and_later_succeed() {
    for (raw, reason) in [
        ("jamnp-stream-reset:2 busy", "Transient"),
        ("jamnp-stream-reset:4 rate limited", "Transient"),
        ("uncoded reset", "Rejected"),
    ] {
        smol::block_on(async {
            let (first, mut config, _, _) = d7_setup(false);
            let (second, _, _, _) = d7_setup(false);
            let platforms = [&first, &second];
            let peer = config.peers.remove(0);
            let params = config.params.clone();
            let root = config.tree.finalized().clone();
            for platform in platforms {
                let mut c = platform.0.lock().unwrap();
                c.io.warps.clear();
                c.responses.clear();
                c.io.block_resets
                    .push_back((Direction::DescendingInclusive, raw));
            }
            let state = driver_state(config);
            state.lock().await.peer_count = 2;
            let follow = state.lock().await.subscribe(16, false);
            future::or(
                future::or(
                    peer_loop(&first, "probe-0", &peer, 0, &params, state.clone()),
                    peer_loop(&second, "probe-1", &peer, 1, &params, state.clone()),
                ),
                future::or(
                    async {
                        loop {
                            if platforms.iter().all(|p| {
                                p.0.lock()
                                    .unwrap()
                                    .io
                                    .logs
                                    .iter()
                                    .any(|s| s == "jam-reconnect")
                            }) {
                                break;
                            }
                            future::yield_now().await;
                        }
                        assert!(!state.lock().await.stopped);
                        assert!(state.lock().await.root_refusals.is_none());
                        assert!(!follow.new_blocks.is_closed());
                        for platform in platforms {
                            assert_reset_log(platform, raw, reason);
                            let mut c = platform.0.lock().unwrap();
                            assert_eq!(c.attempts, 1);
                            assert_eq!(c.requests.len(), 2);
                            let mut block = root.encoded.clone();
                            block.extend([0; 7]);
                            c.responses.insert(root.hash, framed(block));
                        }
                        loop {
                            if platforms
                                .iter()
                                .all(|p| p.0.lock().unwrap().requests.len() >= 3)
                            {
                                break;
                            }
                            future::yield_now().await;
                        }
                        // Let the successful root response reach the driver. A lost
                        // probe would issue another ascending request before this one.
                        smol::Timer::after(Duration::from_millis(100)).await;
                        for platform in platforms {
                            let c = platform.0.lock().unwrap();
                            assert_eq!(c.attempts, 2);
                            assert_eq!(c.requests.len(), 3);
                            assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
                            assert!(c.requests[1..].iter().all(|r| r.hash == root.hash
                                && r.direction == Direction::DescendingInclusive));
                            assert!(!c.io.logs.iter().any(|s| s == "jam-anchor-unserved"));
                        }
                        assert!(!state.lock().await.stopped);
                        assert!(state.lock().await.root_refusals.is_none());
                        assert!(!follow.new_blocks.is_closed());
                    },
                    async {
                        smol::Timer::after(Duration::from_secs(10)).await;
                        panic!("root probe retry timed out: {raw}");
                    },
                ),
            )
            .await;
        });
    }
}

#[test]
fn uncoded_root_ascending_reset_drops_connection_without_arming_probe() {
    smol::block_on(async {
        let (platform, config, _, _) = d7_setup(false);
        let params = config.params.clone();
        let root = config.tree.finalized().hash;
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.io.block_resets
                .push_back((Direction::AscendingExclusive, "uncoded ascending reset"));
        }
        let state = driver_state(config);
        let mut probe = None;
        let connected = platform
            .connect_multistream(MultiStreamAddress::WebTransport {
                ip: "127.0.0.1".parse().unwrap(),
                port: 4433,
                cert_hashes: Cow::Owned(vec![[1; 32]; 3]),
            })
            .await;
        future::or(
            drive(
                &platform,
                "uncoded",
                &params,
                0,
                &state,
                connected.connection,
                (&mut FetchSize::default(), &mut probe),
            ),
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("uncoded reset did not disconnect");
            },
        )
        .await;
        assert_eq!(probe, None);
        assert!(state.lock().await.root_refusals.is_none());
        assert!(!state.lock().await.stopped);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests.len(), 1);
        assert_eq!(c.requests[0].hash, root);
        assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
        assert_eq!(c.io.live_connections, 0);
        drop(c);
        assert_reset_log(&platform, "uncoded ascending reset", "Rejected");
    });
}

#[test]
fn reconnect_discards_retained_probe_after_finalized_root_changes() {
    smol::block_on(async {
        let (platform, config, headers, _) = d7_setup(false);
        let params = config.params.clone();
        let old_root = config.tree.finalized().hash;
        let state = driver_state(config);
        let mut probe = Some(old_root);
        // Another peer finalizes while this peer's root probe awaits reconnect.
        let new_root = {
            let mut s = state.lock().await;
            for header in headers {
                let hash = header.hash(&params);
                s.insert(header, 1_900_000_000).unwrap();
                let proof = platform.0.lock().unwrap().io.proofs.get(&hash).cloned();
                if let Some(proof) = proof {
                    s.finalize(hash, &proof[4..]).unwrap();
                    break;
                }
            }
            s.tree.finalized().hash
        };
        assert_ne!(new_root, old_root);
        {
            let mut c = platform.0.lock().unwrap();
            // Do not let a successful warp clear the probe instead of drive's
            // entry check. Stop at the first ordinary ascending request.
            c.io.warps.clear();
            c.io.block_resets
                .push_back((Direction::AscendingExclusive, "scripted reconnect reset"));
        }
        let connected = platform
            .connect_multistream(MultiStreamAddress::WebTransport {
                ip: "127.0.0.1".parse().unwrap(),
                port: 4433,
                cert_hashes: Cow::Owned(vec![[1; 32]; 3]),
            })
            .await;
        future::or(
            drive(
                &platform,
                "stale-probe",
                &params,
                0,
                &state,
                connected.connection,
                (&mut FetchSize::default(), &mut probe),
            ),
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("stale-probe reconnect did not finish");
            },
        )
        .await;
        assert_eq!(probe, None);
        assert!(state.lock().await.root_refusals.is_none());
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests.len(), 1);
        assert!(c.requests.iter().all(|request| request.hash != old_root));
        assert_eq!(c.requests[0].hash, new_root);
        assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
    });
}

#[test]
fn warp_rate_limit_drops_connection_and_other_peer_completes() {
    smol::block_on(async {
        let (limited, mut config, _, _) = d7_setup(true);
        let (serving, _, _, _) = d7_setup(true);
        limited
            .0
            .lock()
            .unwrap()
            .io
            .warp_resets
            .push_back("jamnp-stream-reset:4 rate limited");
        let peer = config.peers.remove(0);
        let params = config.params.clone();
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        future::or(
            peer_loop(&limited, "limited", &peer, 0, &params, state.clone()),
            future::or(
                async {
                    loop {
                        if limited
                            .0
                            .lock()
                            .unwrap()
                            .io
                            .logs
                            .iter()
                            .any(|s| s == "jam-reconnect")
                        {
                            break;
                        }
                        future::yield_now().await;
                    }
                    assert_eq!(state.lock().await.warp_owner, None);
                    assert_eq!(state.lock().await.warp_revision, 0);
                    assert!(
                        limited.0.lock().unwrap().requests.is_empty(),
                        "rate limit must not enter warp tail or ordinary sync"
                    );
                    future::or(
                        peer_loop(&serving, "serving", &peer, 1, &params, state.clone()),
                        async {
                            while state.lock().await.warp_revision == 0 {
                                future::yield_now().await;
                            }
                        },
                    )
                    .await;
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("warp rate limit failover timed out");
                },
            ),
        )
        .await;
        assert_eq!(state.lock().await.warp_revision, 1);
        assert!(!state.lock().await.stopped);
        assert_reset_log(&limited, "jamnp-stream-reset:4 rate limited", "Transient");
        let c = limited.0.lock().unwrap();
        assert_eq!(c.attempts, 1);
        assert_eq!(c.io.live_connections, 0);
        assert_eq!(c.io.warp_requests, [0]);
        assert!(
            c.io.log_fields
                .iter()
                .any(|(message, fields)| message == "jam-warp-rejected"
                    && fields.get("reason").map(String::as_str) == Some("Transient"))
        );
        assert!(
            serving
                .0
                .lock()
                .unwrap()
                .io
                .logs
                .iter()
                .any(|s| s == "jam-warp-applied")
        );
    });
}

#[test]
fn typed_proof_resets_release_reservation_without_disconnecting() {
    for (raw, reason) in [
        ("jamnp-stream-reset:6 no proof", "NoData"),
        ("jamnp-stream-reset:2 busy proof", "Transient"),
    ] {
        smol::block_on(async {
            let (platform, config, headers, _) = d7_setup(false);
            let params = config.params.clone();
            let root_slot = config.tree.finalized().slot;
            let tip = &headers[headers.len() - 2];
            {
                let mut c = platform.0.lock().unwrap();
                c.io.warps.clear();
                c.io.proof_resets.push_back(raw);
            }
            let state = driver_state(config);
            future::or(
                async {
                    d7_drive(&platform, &params, &state, 0, 1).await;
                    panic!("proof reset disconnected: {raw}");
                },
                future::or(
                    async {
                        while state.lock().await.tree.best().slot < tip.slot {
                            future::yield_now().await;
                        }
                    },
                    async {
                        smol::Timer::after(Duration::from_secs(10)).await;
                        panic!("proof retry timed out: {raw}");
                    },
                ),
            )
            .await;
            assert_reset_log(&platform, raw, reason);
            let mut s = state.lock().await;
            assert_eq!(s.tree.finalized().slot, root_slot);
            assert!(s.proof_owner.is_none());
            // The first unavailable set-change proof still blocks finality,
            // but another peer remains free to serve it.
            assert!(
                s.reserve_proof(
                    1,
                    &Final {
                        hash: tip.hash(&params),
                        slot: tip.slot
                    }
                )
                .is_some()
            );
            let c = platform.0.lock().unwrap();
            assert_eq!(c.attempts, 1);
            assert_eq!(c.io.proof_requests.len(), 1);
        });
    }
}

#[test]
fn warp_reservation_and_refusals_are_snapshot_scoped() {
    let mut s = root_state();
    let root = s.tree.finalized().hash;
    s.proof_owner = Some((0, root));
    assert!(s.reserve_warp(1).is_none());
    s.proof_owner = None;
    assert!(s.reserve_warp(0).is_some());
    assert!(s.reserve_warp(1).is_none());
    assert_eq!(
        s.reserve_proof(
            1,
            &Final {
                hash: root,
                slot: 10
            }
        ),
        None
    );
    s.warp_owner = None;
    assert!(s.refuse_root(0, root).is_ok());
    assert!(s.refuse_root(0, root).is_ok());
    assert!(s.refuse_root(1, [99; 32]).is_ok());
    assert_eq!(
        s.refuse_root(1, root),
        Err(AnchorUnserved {
            hash: root,
            slot: s.tree.finalized().slot
        })
    );
}

#[test]
fn join_authenticates_exact_final_head_before_reading() {
    let (_, config, _, _) = d7_setup(false);
    let s = smol::block_on(async {
        Arc::try_unwrap(driver_state(config))
            .ok()
            .unwrap()
            .into_inner()
    });
    let vector = join_vector();
    let head = join_exchange(&vector, "join-head");
    let blocks =
        smoldot::jam::types::Block::decode_sequence(&s.params, &head[4..], FRAME_BYTES, 1).unwrap();
    for failure in 0..4 {
        let mut w = Warp::new(&s);
        w.final_head = Some(Final {
            hash: blocks[0].header.hash(&s.params),
            slot: blocks[0].header.slot,
        });
        let mut bad = blocks.clone();
        match failure {
            0 => {
                bad[0].header.prior_state_root[0] ^= 1;
            }
            1 => {
                bad.push(bad[0].clone());
            }
            2 => {
                bad.pop();
            }
            _ => {
                w.final_head.as_mut().unwrap().slot += 1;
            }
        }
        assert!(matches!(
            w.receive_headers(&s.params, bad, s.header_bytes),
            Err(WarpError::InvalidJoin)
        ));
        assert!(w.next_read().is_err());
    }
}

#[test]
fn staged_join_failure_is_atomic_for_header_state_and_tree_errors() {
    smol::block_on(async {
        for failure in 0..4 {
            let (mut s, mut w) = captured_join().await;
            let old_root = s.tree.finalized().clone();
            let old_authorities = s.authorities.clone();
            let follow = s.subscribe(16, false);
            match failure {
                0 => w.finalized = None,
                // F's header must be the one its justification finalized.
                1 => w.head.as_mut().unwrap().seal[0] ^= 1,
                2 => w.items[3].1 = 0u32.to_le_bytes().to_vec(),
                _ => s.tree_config.max_bytes = 1,
            }
            let result = s.apply_warp(0, w);
            match failure {
                0..=2 => assert!(matches!(result, Err(WarpError::InvalidJoin))),
                _ => assert!(matches!(result, Err(WarpError::Tree(_)))),
            }
            assert_eq!(s.tree.finalized(), &old_root);
            assert_eq!(s.authorities, old_authorities);
            assert_eq!(s.warp_revision, 0);
            assert!(!follow.new_blocks.is_closed());
        }
    });
}

#[test]
fn join_epoch_finality_rotates_exactly_once_and_finalizes_child() {
    smol::block_on(async {
        use smoldot::identity::keystore::{KeyNamespace, Keystore};
        let vector = join_vector();
        let epoch = &vector["epoch_join_regression"];
        let spec = JamChainSpec::from_json_bytes(vector["spec"].to_string().as_bytes()).unwrap();
        let params = spec.params();
        let f = Header::decode(params, &bytes(&epoch["finalized_header_hex"])).unwrap();
        let p = Header::decode(params, &bytes(&epoch["parent_header_hex"])).unwrap();
        let child = Header::decode(params, &bytes(&epoch["child_header_hex"])).unwrap();
        let f_root: Hash = bytes(&epoch["finalized_post_state_root"])
            .try_into()
            .unwrap();
        assert_eq!(f_root, child.prior_state_root);
        let state_items = |name: &str| -> Vec<(trie::StateKey, Vec<u8>)> {
            epoch[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        bytes(&item["key_hex"]).try_into().unwrap(),
                        bytes(&item["value_hex"]),
                    )
                })
                .collect()
        };
        let anchor = |items: &[(trie::StateKey, Vec<u8>)]| {
            LightState::from_anchor(
                params,
                &GenesisLightState::from_state_items(
                    params,
                    items.iter().map(|(k, v)| (k, v.as_slice())),
                )
                .unwrap(),
            )
            .unwrap()
        };
        // Anchoring at F on its posterior state equals the former P-to-F step.
        let stepped = smoldot::jam::verify::verify_header(
            params,
            &verified_genesis(
                params,
                p.clone(),
                anchor(&state_items("parent_state_items")),
            ),
            f.clone(),
            1_900_000_000,
        )
        .unwrap();
        assert_eq!(
            anchor(&state_items("finalized_state_items")),
            stepped.post_state
        );
        let keys = Keystore::new(None, [77; 32]).await.unwrap();
        let a = keys
            .generate_ed25519(KeyNamespace::Grandpa, false)
            .await
            .unwrap();
        let b = keys
            .generate_ed25519(KeyNamespace::Grandpa, false)
            .await
            .unwrap();
        assert_ne!(a, b);
        let next: Vec<_> = f
            .epoch_mark
            .as_ref()
            .unwrap()
            .validators
            .iter()
            .map(|(_, ed)| *ed)
            .collect();
        assert_ne!(next, vec![a; 6]);
        assert_ne!(next, vec![b; 6]);
        let mut previous = f.clone();
        previous.slot -= params.epoch_len;
        for (_, ed) in &mut previous.epoch_mark.as_mut().unwrap().validators {
            *ed = a;
        }
        let previous_proof = scripted_join_proof(&keys, a, params, &previous, [0; 32], 7).await;
        let f_proof = scripted_join_proof(&keys, b, params, &f, f_root, 8).await;
        let child_proof = scripted_join_proof(&keys, a, params, &child, [0; 32], 9).await;
        for consumed in [false, true] {
            for failure in 0..3 {
                let mut config = Config::from_spec(&spec).unwrap();
                config.authorities =
                    AuthoritySet::from_checkpoint(params, 7, vec![a; 6], vec![b; 6]).unwrap();
                let mut s = Arc::try_unwrap(driver_state(config))
                    .ok()
                    .unwrap()
                    .into_inner();
                let original_root = s.tree.finalized().clone();
                let original_authorities = s.authorities.clone();
                let follower = s.subscribe(16, false);
                let limits = finality::WarpLimits {
                    max_fragments: 32,
                    max_header_bytes: s.header_bytes,
                    proof: s.proof_limits(),
                };
                let mut w = s.reserve_warp(0).unwrap();
                let mut fragments = vec![if consumed { 2 } else { 1 }];
                fragments.extend(previous.encode(params));
                fragments.extend(&previous_proof);
                if consumed {
                    fragments.extend(f.encode(params));
                    fragments.extend(&f_proof);
                }
                w.advance(params, &fragments, &limits).unwrap();
                assert!(w.chain_done);
                assert_eq!(w.authorities.set_id(), if consumed { 9 } else { 8 });
                w.final_head = Some(Final {
                    hash: f.hash(params),
                    slot: f.slot,
                });
                w.receive_headers(
                    params,
                    vec![smoldot::jam::types::Block {
                        header: f.clone(),
                        body: vec![],
                    }],
                    s.header_bytes,
                )
                .unwrap();
                assert_eq!(w.finalized.is_some(), consumed);
                if consumed {
                    // F's genuine outgoing-set proof cannot be checked under set 9;
                    // the exact verified fragment is the already-consumed evidence.
                    assert_eq!(
                        Justification::decode(params, &f_proof, limits.proof)
                            .unwrap()
                            .set_id(),
                        8
                    );
                    // The fragment's signed root is the one the join reads against.
                    assert_eq!(w.next_read().unwrap().root, f_root);
                    let mut other = Warp::new(&s);
                    other.last_final = w.last_final;
                    other.authorities = w.authorities.clone();
                    let mut different = f.clone();
                    different.seal[0] ^= 1;
                    other.final_head = Some(Final {
                        hash: different.hash(params),
                        slot: different.slot,
                    });
                    other
                        .receive_headers(
                            params,
                            vec![smoldot::jam::types::Block {
                                header: different,
                                body: vec![],
                            }],
                            s.header_bytes,
                        )
                        .unwrap();
                    assert!(
                        other.finalized.is_none(),
                        "same slot is not the same finalized target"
                    );
                    assert!(other.next_read().is_err());
                } else {
                    assert!(w.next_read().is_err());
                    let before = w.authorities.clone();
                    let mut bad = f_proof.clone();
                    bad[90] ^= 1;
                    assert!(w.authenticate(params, &bad, limits.proof).is_err());
                    assert_eq!(w.authorities, before);
                    assert!(w.finalized.is_none());
                    w.authenticate(params, &f_proof, limits.proof).unwrap();
                    assert_eq!(w.next_read().unwrap().root, f_root);
                }
                assert_eq!(w.authorities.set_id(), 9);
                assert_eq!(w.authorities.current(), vec![a; 6]);
                assert_eq!(w.authorities.next(), next);
                assert!(
                    w.authenticate(params, &f_proof, limits.proof).is_err(),
                    "cannot consume F twice"
                );
                w.items = state_items("finalized_state_items");
                match failure {
                    1 => w.head.as_mut().unwrap().seal[0] ^= 1,
                    2 => s.tree_config.max_bytes = 1,
                    _ => {}
                }
                let result = s.apply_warp(0, w);
                if failure != 0 {
                    assert!(result.is_err());
                    assert_eq!(s.tree.finalized(), &original_root);
                    assert_eq!(s.authorities, original_authorities);
                    assert_eq!(s.warp_revision, 0);
                    assert!(!follower.new_blocks.is_closed());
                    continue;
                }
                result.unwrap();
                assert!(follower.new_blocks.is_closed());
                assert_eq!(s.tree.finalized().hash, f.hash(params));
                assert_eq!(s.authorities.set_id(), 9);
                assert_eq!(s.authorities.current(), vec![a; 6]);
                assert_eq!(s.authorities.next(), next);
                s.insert(child.clone(), 1_900_000_000).unwrap();
                s.finalize(child.hash(params), &child_proof).unwrap();
                assert_eq!(s.tree.finalized().hash, child.hash(params));
                assert_eq!(s.authorities.set_id(), 9);
            }
        }
    });
}

#[test]
fn join_bad_state_justification_header_and_resets_retry_other_peer() {
    smol::block_on(async {
        use smoldot::identity::keystore::{KeyNamespace, Keystore};
        for failure in 0..5 {
            let (bad, mut config, _, f) = join_setup();
            let (good, _, _, _) = join_setup();
            let params = config.params.clone();
            let peer = config.peers.remove(0);
            if failure == 2 {
                // A valid justification for F that signs another posterior root:
                // the served state cannot be proven against it.
                let keys = Keystore::new(None, [42; 32]).await.unwrap();
                let public = keys
                    .generate_ed25519(KeyNamespace::Grandpa, false)
                    .await
                    .unwrap();
                let proof =
                    framed(scripted_join_proof(&keys, public, &params, &f, [0xee; 32], 3).await);
                bad.0
                    .lock()
                    .unwrap()
                    .io
                    .proofs
                    .insert(f.hash(&params), proof);
            } else {
                let mut c = bad.0.lock().unwrap();
                match failure {
                    0 => {
                        let Ok(frame) = c.io.state_responses.front_mut().unwrap() else {
                            unreachable!()
                        };
                        *frame.last_mut().unwrap() ^= 1;
                    }
                    1 => {
                        let proof = c.io.proofs.get_mut(&f.hash(&params)).unwrap();
                        proof[90] ^= 1;
                    }
                    3 => {
                        c.io.proof_resets
                            .push_back("jamnp-stream-reset:6 no advertised proof")
                    }
                    _ => c.io.state_responses[0] = Err("jamnp-stream-reset:4 too soon"),
                }
            }
            let state = driver_state(config);
            state.lock().await.peer_count = 2;
            let root = state.lock().await.tree.finalized().clone();
            let follow = state.lock().await.subscribe(16, false);
            future::or(
                peer_loop(&bad, "join-bad", &peer, 0, &params, state.clone()),
                async {
                    let wait = async {
                        loop {
                            if !bad.0.lock().unwrap().io.warp_requests.is_empty()
                                && state.lock().await.warp_owner.is_none()
                            {
                                break;
                            }
                            future::yield_now().await;
                        }
                    };
                    future::or(wait, async {
                        smol::Timer::after(Duration::from_secs(10)).await;
                        panic!("bad join did not release, case {failure}");
                    })
                    .await;
                },
            )
            .await;
            assert_eq!(state.lock().await.tree.finalized(), &root);
            assert_eq!(state.lock().await.warp_revision, 0);
            assert!(!follow.new_blocks.is_closed());
            if failure == 1 || failure == 3 {
                assert!(
                    bad.0.lock().unwrap().io.state_requests.is_empty(),
                    "root must not be trusted before CE130"
                );
            }
            future::or(
                async {
                    d7_drive(&good, &params, &state, 1, 64).await;
                    panic!("healthy join disconnected, case {failure}");
                },
                future::or(
                    async {
                        while state.lock().await.warp_revision == 0 {
                            future::yield_now().await;
                        }
                    },
                    async {
                        smol::Timer::after(Duration::from_secs(10)).await;
                        panic!("healthy join timed out, case {failure}");
                    },
                ),
            )
            .await;
            assert!(follow.new_blocks.is_closed());
            assert_eq!(good.0.lock().unwrap().io.state_requests.len(), 4);
        }
    });
}

fn driver_state(config: Config) -> Arc<async_lock::Mutex<State>> {
    Arc::new(async_lock::Mutex::new(State {
        reads: StateReads::default(),
        #[cfg(test)]
        test_verifier: None,
        tree: config.tree,
        params: config.params,
        subscribers: vec![],
        stopped: false,
        header_bytes: config.header_bytes,
        authorities: config.authorities,
        max_blocks: config.max_blocks,
        proof_owner: None,
        proof_attempts: vec![],
        tree_config: config.tree_config,
        warp_owner: None,
        warp_revision: 0,
        root_refusals: None,
        peer_count: config.peers.len(),
    }))
}

#[test]
fn state_read_scripted_driver_retries_proof_nodata_and_transient() {
    smol::block_on(async {
        for failure in [0, 1, 2, 3] {
            let state = Arc::new(async_lock::Mutex::new(root_state()));
            let params = state.lock().await.params.clone();
            let final_ = Final {
                hash: state.lock().await.tree.finalized().hash,
                slot: 0,
            };
            let platform = FakePlatform(Arc::new(Mutex::new(Control {
                handshake: framed(
                    Handshake {
                        final_: final_.clone(),
                        leaves: vec![],
                    }
                    .encode(),
                ),
                responses: Default::default(),
                requests: vec![],
                attempts: 0,
                fail_first: false,
                supported: true,
                pins: vec![],
                disconnect: false,
                starve: false,
                queued: false,
                clock_shift: Duration::ZERO,
                io: IoState::default(),
            })));
            let key = trie::state_key(8);
            let value = vec![7; 336 * 6 + 2];
            let mut node = [0; 64];
            node[0] = 0xc0;
            node[1..32].copy_from_slice(&key);
            node[32..].copy_from_slice(&smoldot::jam::crypto::blake2b_256(&value));
            let root = smoldot::jam::crypto::blake2b_256(&node);
            let mut entries = key.to_vec();
            entries.extend(smoldot::jam::codec::encode_natural(
                u64::try_from(value.len()).unwrap(),
            ));
            entries.extend(&value);
            let mut good = framed(node.to_vec());
            good.extend(framed(entries));
            let first = match failure {
                0 => {
                    let mut bad = good.clone();
                    *bad.last_mut().unwrap() ^= 1;
                    Ok(bad)
                }
                1 => Err("jamnp-stream-reset:6 no state"),
                _ => Err("jamnp-stream-reset:3 busy"),
            };
            if failure == 3 {
                let mut control = platform.0.lock().unwrap();
                control.io.stall_outbound = true;
                control.io.state_responses = [Ok(good)].into();
            } else {
                platform.0.lock().unwrap().io.state_responses = [first, Ok(good)].into();
            }
            // Authenticate two scripted headers, finalize the first with a real
            // signature, and read its state against the second's prior root.
            let read = {
                use smoldot::identity::keystore::{KeyNamespace, Keystore};
                let keys = Keystore::new(None, [42; 32]).await.unwrap();
                let public = keys
                    .generate_ed25519(KeyNamespace::Grandpa, false)
                    .await
                    .unwrap();
                let mut s = state.lock().await;
                assert!(s.finalized_read(key, key, 4000).is_none());
                s.authorities =
                    AuthoritySet::from_checkpoint(&params, 0, vec![public; 6], vec![public; 6])
                        .unwrap();
                let mut header = Header::decode(&params, &s.tree.finalized().encoded).unwrap();
                let mut target = [0; 32];
                for slot in 1..=2 {
                    let parent = s.tree.best().clone();
                    header.parent = parent.hash;
                    header.slot = slot;
                    header.prior_state_root = root;
                    let verified =
                        verified_genesis(&params, header.clone(), parent.post_state.clone());
                    if slot == 1 {
                        target = verified.hash;
                    }
                    s.tree.insert_verified(parent.hash, verified).unwrap();
                }
                let mut payload = b"jam_grandpa_vote".to_vec();
                payload.push(1);
                payload.extend(target);
                payload.extend(root);
                payload.extend(1u32.to_le_bytes());
                payload.extend(1u64.to_le_bytes());
                payload.extend(0u32.to_le_bytes());
                let signature = keys
                    .sign(KeyNamespace::Grandpa, &public, &payload)
                    .await
                    .unwrap();
                let mut proof = 1u64.to_le_bytes().to_vec();
                proof.extend(0u32.to_le_bytes());
                proof.extend(target);
                proof.extend(root);
                proof.extend(1u32.to_le_bytes());
                proof.push(1);
                proof.extend(target);
                proof.extend(root);
                proof.extend(1u32.to_le_bytes());
                proof.extend(signature);
                proof.extend(public);
                proof.push(0);
                s.finalize(target, &proof).unwrap();
                let read = s.finalized_read(key, key, 4000).unwrap();
                assert_eq!(read.at, target);
                assert_eq!(read.root, root);
                assert_eq!(read.root_header, Some(s.tree.best().hash));
                read
            };
            let rx = state.lock().await.reads.start(read.clone()).unwrap();
            // Run failing peer first. NoData leaves the connection alive, so end
            // that turn as soon as it releases the shared reservation.
            let connection = || {
                platform.0.lock().unwrap().io.live_connections += 1;
                FakeConnection {
                    control: platform.0.clone(),
                    streams: VecDeque::new(),
                    number: 0,
                    dead: false,
                }
            };
            let mut fetch = FetchSize::default();
            future::or(
                drive(
                    &platform,
                    "state-test",
                    &params,
                    0,
                    &state,
                    connection(),
                    (&mut fetch, &mut None),
                ),
                async {
                    let mut shifted = false;
                    loop {
                        if failure == 3 {
                            let owner = state.lock().await.reads.owner;
                            if owner.is_some() && !shifted {
                                platform.0.lock().unwrap().clock_shift = Duration::from_secs(21);
                                shifted = true;
                            }
                            if shifted && owner.is_none() {
                                break;
                            }
                        } else if !platform.0.lock().unwrap().io.state_requests.is_empty()
                            && state.lock().await.reads.owner.is_none()
                        {
                            break;
                        }
                        future::yield_now().await;
                    }
                },
            )
            .await;
            // Same connection teardown cleanup as peer_loop (also covers an
            // opening deadline firing before the queued read's deadline).
            state.lock().await.reads.release(0, false);
            platform.0.lock().unwrap().io.stall_outbound = false;
            let peer = if failure == 2 { 0 } else { 1 };
            if failure != 2 {
                assert!(state.lock().await.reads.reserve(0).is_none());
            }
            let mut fetch = FetchSize::default();
            let result = future::or(
                async {
                    drive(
                        &platform,
                        "state-test",
                        &params,
                        peer,
                        &state,
                        connection(),
                        (&mut fetch, &mut None),
                    )
                    .await;
                    panic!("successful driver exited")
                },
                async { rx.await.unwrap().unwrap() },
            )
            .await;
            assert_eq!(
                (result.at, result.root, result.trust),
                (read.at, read.root, read.trust)
            );
            assert_eq!(result.range.entries, vec![(key, value)]);
            assert_eq!(result.root_header, read.root_header);
            assert_eq!(
                platform.0.lock().unwrap().io.state_requests,
                vec![read.request.encode().to_vec(); if failure == 3 { 1 } else { 2 }]
            );
        }
    });
}

#[test]
#[ignore = "requires external A5 fake-platform identity fixture"]
fn external_full_parameter_1200_blocks_interleave_finality() {
    smol::block_on(async {
        use smoldot::{
            identity::keystore::{KeyNamespace, Keystore},
            jam::{codec, types::EpochMark, verify::VerifiedHeader},
        };
        let (platform, _, _, _) = fixture_setup();
        let keys = Keystore::new(None, [42; 32]).await.unwrap();
        let public = keys
            .generate_ed25519(KeyNamespace::Grandpa, false)
            .await
            .unwrap();
        let mut params = root_state().params;
        params.epoch_len = 600;
        params.epoch_tail_start = 500;
        params.max_validators = 1023;
        params.core_count = 341;
        let (header_bytes, limits) = memory_limits(&params).unwrap();
        let pairs = vec![([0; 32], public); 1023];
        let mut header = Header::decode(&params, &root_state().tree.finalized().encoded).unwrap();
        header.slot = 0;
        let root = verified_genesis(
            &params,
            header.clone(),
            LightState::from_parts(
                [[0; 32]; 4],
                pairs.clone(),
                pairs.clone(),
                SealingSequence::Keys(vec![[0; 32]; 600]),
                None,
                0,
            ),
        );
        let mut headers = Vec::new();
        let mut proofs = BTreeMap::new();
        let mut parent = root.hash;
        for slot in 1u32..=1200 {
            header.parent = parent;
            header.slot = slot;
            header.epoch_mark = (slot % 600 == 0).then(|| EpochMark {
                entropy: [0; 32],
                tickets_entropy: [0; 32],
                validators: pairs.clone(),
            });
            let hash = header.hash(&params);
            let set_id = (slot - 1) / 600;
            // PolkaJam's signed precommit: domain, tag, hash, posterior state root,
            // slot, round, set. Every header here has the same prior state root.
            let root = header.prior_state_root;
            let mut payload = b"jam_grandpa_vote".to_vec();
            payload.push(1);
            payload.extend(hash);
            payload.extend(root);
            payload.extend(slot.to_le_bytes());
            payload.extend(1u64.to_le_bytes());
            payload.extend(set_id.to_le_bytes());
            let signature = keys
                .sign(KeyNamespace::Grandpa, &public, &payload)
                .await
                .unwrap();
            let mut proof = 1u64.to_le_bytes().to_vec();
            proof.extend(set_id.to_le_bytes());
            proof.extend(hash);
            proof.extend(root);
            proof.extend(slot.to_le_bytes());
            proof.extend(codec::encode_natural(1));
            proof.extend(hash);
            proof.extend(root);
            proof.extend(slot.to_le_bytes());
            proof.extend(signature);
            proof.extend(public);
            proof.extend(codec::encode_natural(0));
            proofs.insert(hash, framed(proof));
            headers.push(header.clone());
            parent = hash;
        }
        {
            let mut control = platform.0.lock().unwrap();
            control.responses.clear();
            control.io.params = Some(params.clone());
            control.io.proofs = proofs;
            for header in &headers {
                let mut block = header.encode(&params);
                block.extend([0; 7]);
                control
                    .responses
                    .insert(header.hash(&params), framed(block));
            }
            control.handshake = framed(
                Handshake {
                    final_: Final {
                        hash: parent,
                        slot: 1200,
                    },
                    leaves: vec![],
                }
                .encode(),
            );
        }
        let config = Config {
            params: params.clone(),
            tree: HeaderTree::new(params.clone(), root, limits).unwrap(),
            peers: vec![],
            header_bytes,
            authorities: AuthoritySet::from_checkpoint(
                &params,
                0,
                vec![public; 1023],
                vec![public; 1023],
            )
            .unwrap(),
            max_blocks: limits.max_blocks.get(),
            tree_config: limits,
        };
        let state = driver_state(config);
        state.lock().await.test_verifier = Some(|params, parent, header| {
            let mut post_state = parent.post_state.clone();
            if let Some(mark) = &header.epoch_mark {
                post_state = LightState::from_parts(
                    post_state.entropy(),
                    post_state.epoch().pending.clone(),
                    mark.validators.clone(),
                    post_state.epoch().sealing.clone(),
                    None,
                    header.slot,
                );
            }
            VerifiedHeader {
                hash: header.hash(params),
                slot: header.slot,
                epoch_changed: header.epoch_mark.is_some(),
                sealed_with_ticket: false,
                encoded: header.encode(params),
                parent: header.parent,
                post_state,
            }
        });
        let subscription = state.lock().await.subscribe(16, false);
        let mut imported = Vec::new();
        let mut peak_nodes = 0;
        let mut peak_bytes = 0;
        future::or(
            async {
                scripted_drive(&platform, &params, &state).await;
                panic!("full-parameter driver disconnected");
            },
            future::or(
                async {
                    loop {
                        if let Notification::Block(block) =
                            subscription.new_blocks.recv().await.unwrap()
                        {
                            imported.push(blake2b_256(&block.scale_encoded_header));
                        }
                        let s = state.lock().await;
                        peak_nodes = peak_nodes.max(s.tree.len());
                        peak_bytes = peak_bytes.max(s.tree.retained_bytes());
                        assert!(s.tree.len() + 64 < s.max_blocks, "no import backpressure");
                        assert!(s.tree.retained_bytes() <= limits.max_bytes);
                        assert!(s.tree.epoch_records() <= 2);
                        assert!(!s.stopped);
                        if s.tree.finalized().slot == 1200 {
                            break;
                        }
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(30)).await;
                    panic!("full-parameter catch-up timed out");
                },
            ),
        )
        .await;
        assert_eq!(
            imported,
            headers.iter().map(|h| h.hash(&params)).collect::<Vec<_>>()
        );
        let control = platform.0.lock().unwrap();
        assert_eq!(control.attempts, 1);
        assert!(!control.io.proof_requests.is_empty());
        assert!(
            control
                .requests
                .iter()
                .all(|r| r.direction == Direction::AscendingExclusive)
        );
        std::println!(
            "D13 full driver: imported={} peak_nodes={peak_nodes} peak_bytes={peak_bytes} max_bytes={} max_blocks={} CE130={} connections={}",
            imported.len(),
            limits.max_bytes,
            limits.max_blocks,
            control.io.proof_requests.len(),
            control.attempts
        );
    });
}

async fn scripted_drive(
    platform: &FakePlatform,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
) {
    let identity = P256PeerId::from_text(
        fixture("cert_vector.json")[0]["p256_id_text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let connected = platform
        .connect_multistream(MultiStreamAddress::WebTransport {
            ip: "127.0.0.1".parse().unwrap(),
            port: 4433,
            cert_hashes: Cow::Owned(
                jam_webtransport_cert::certificate_hashes(&identity, 1_800_000_000).to_vec(),
            ),
        })
        .await;
    drive(
        platform,
        "scripted",
        params,
        0,
        state,
        connected.connection,
        (&mut FetchSize::default(), &mut None),
    )
    .await;
}

#[test]
#[ignore = "requires external deterministic D14 signed corpus; fixtures/d14/generator"]
fn external_ascending_600_blocks_interleaves_finality_without_reconnect() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(600, 32);
        let params = config.params.clone();
        let root = config.tree.finalized().hash;
        let state = driver_state(config);
        let subscription = state.lock().await.subscribe(16, false);
        let mut imported = Vec::new();
        let mut peak = 0;
        future::or(
            async {
                scripted_drive(&platform, &params, &state).await;
                panic!("driver disconnected before catch-up completed");
            },
            future::or(
                async {
                    loop {
                        let event = subscription.new_blocks.recv().await.unwrap();
                        if let Notification::Block(block) = event {
                            imported.push(blake2b_256(&block.scale_encoded_header));
                        }
                        let s = state.lock().await;
                        peak = peak.max(s.tree.len());
                        assert!(s.tree.len() <= s.max_blocks);
                        if s.tree.finalized().slot == 600 {
                            break;
                        }
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(30)).await;
                    panic!("600-block catch-up timed out");
                },
            ),
        )
        .await;
        let expected: Vec<_> = headers.iter().map(|h| h.hash(&params)).collect();
        assert_eq!(imported, expected);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 1);
        assert_eq!(c.requests.len(), 15);
        assert!(
            c.requests
                .iter()
                .all(|r| r.direction == Direction::AscendingExclusive
                    && (1..=64).contains(&r.max_blocks))
        );
        assert_eq!(
            c.requests.iter().map(|r| r.hash).collect::<Vec<_>>(),
            [
                0, 1, 3, 7, 15, 31, 63, 127, 191, 255, 319, 383, 447, 511, 575
            ]
            .into_iter()
            .map(|index| if index == 0 {
                root
            } else {
                expected[index - 1]
            })
            .collect::<Vec<_>>()
        );
        for header in headers.iter().filter(|h| h.epoch_mark.is_some()) {
            assert!(c.io.proof_requests.contains(&header.hash(&params)));
        }
        std::println!(
            "D14 multi: imported=600 CE128={} CE130={} retained_peak={peak}/32 connections={}",
            c.requests.len(),
            c.io.proof_requests.len(),
            c.attempts
        );
    });
}

#[test]
#[ignore = "requires external deterministic D14 signed corpus; fixtures/d14/generator"]
fn external_dead_first_child_escapes_through_bounded_announcement_repair() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(10, 32);
        let params = config.params.clone();
        let root = config.tree.finalized().hash;
        let dead = Header::decode(
            &params,
            &bytes(&fixture("d15/synthetic.json")["dead_header"]),
        )
        .unwrap();
        let dead_hash = dead.hash(&params);
        {
            let mut c = platform.0.lock().unwrap();
            c.io.proofs.clear();
            c.io.preferred_child = Some((dead.parent, dead_hash));
            let mut block = dead.encode(&params);
            block.extend([0; 7]);
            c.responses.insert(dead_hash, framed(block));
            c.io.fork_announcement = Some(framed(
                smoldot::jam::types::Announcement {
                    header: headers[9].clone(),
                    final_: Final {
                        hash: root,
                        slot: 0,
                    },
                }
                .encode(&params),
            ));
        }
        let state = driver_state(config);
        future::or(
            async {
                scripted_drive(&platform, &params, &state).await;
                panic!("fork recovery disconnected");
            },
            future::or(
                async {
                    loop {
                        if state.lock().await.tree.best().hash == headers[9].hash(&params) {
                            break;
                        }
                        future::yield_now().await;
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(15)).await;
                    panic!("fork recovery timed out");
                },
            ),
        )
        .await;
        let s = state.lock().await;
        assert!(
            s.tree.get(&dead_hash).is_some(),
            "peer opinion must not remove authenticated best"
        );
        assert_eq!(s.tree.finalized().hash, root);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 1);
        assert_eq!(
            c.io.no_blocks, 2,
            "best reset, then repeated dead fallback reset"
        );
        assert!(
            c.requests
                .iter()
                .filter(|r| r.direction == Direction::DescendingInclusive)
                .count()
                <= REPAIR_LIMIT
        );
        assert_eq!(c.requests.iter().filter(|r| r.hash == root).count(), 2);
        std::println!(
            "D14 fork: live_tip=10 resets={} CE128={} connections={}",
            c.io.no_blocks,
            c.requests.len(),
            c.attempts
        );
    });
}

#[test]
#[ignore = "requires external deterministic D14 signed corpus; fixtures/d14/generator"]
fn external_full_unfinalizable_tree_exits_instead_of_deadlocking() {
    smol::block_on(async {
        let (platform, config, _) = synthetic_driver(10, 4);
        let params = config.params.clone();
        platform.0.lock().unwrap().io.proofs.clear();
        let state = driver_state(config);
        future::or(scripted_drive(&platform, &params, &state), async {
            smol::Timer::after(Duration::from_secs(10)).await;
            panic!("full unfinalizable tree deadlocked");
        })
        .await;
        let s = state.lock().await;
        assert_eq!(s.tree.len(), 4);
        assert_eq!(s.tree.finalized().slot, 0);
        assert!(
            !s.stopped,
            "dropping the peer leaves shared state available"
        );
    });
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

#[test]
#[ignore = "requires external deterministic D14 signed corpus; fixtures/d14/generator"]
fn external_oversized_batch_retries_with_persistent_lower_ceiling() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(10, 32);
        let params = config.params.clone();
        let state = driver_state(config);
        platform.0.lock().unwrap().io.reject_batch_above = Some(2);
        let identity = P256PeerId::from_text(
            fixture("cert_vector.json")[0]["p256_id_text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut size = FetchSize {
            count: 8,
            ceiling: 64,
        };
        for expected in [4, 2] {
            let connected = platform
                .connect_multistream(MultiStreamAddress::WebTransport {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 4433,
                    cert_hashes: Cow::Owned(
                        jam_webtransport_cert::certificate_hashes(&identity, 1_800_000_000)
                            .to_vec(),
                    ),
                })
                .await;
            future::or(
                drive(
                    &platform,
                    "oversized",
                    &params,
                    0,
                    &state,
                    connected.connection,
                    (&mut size, &mut None),
                ),
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("oversized response did not terminate the driver");
                },
            )
            .await;
            assert_eq!(size.count, expected);
            assert_eq!(state.lock().await.tree.len(), 1);
        }
        let connected = platform
            .connect_multistream(MultiStreamAddress::WebTransport {
                ip: "127.0.0.1".parse().unwrap(),
                port: 4433,
                cert_hashes: Cow::Owned(
                    jam_webtransport_cert::certificate_hashes(&identity, 1_800_000_000).to_vec(),
                ),
            })
            .await;
        future::or(
            async {
                drive(
                    &platform,
                    "resized",
                    &params,
                    0,
                    &state,
                    connected.connection,
                    (&mut size, &mut None),
                )
                .await;
                panic!("resized batch disconnected");
            },
            future::or(
                async {
                    loop {
                        if state.lock().await.tree.best().hash == headers[9].hash(&params) {
                            break;
                        }
                        future::yield_now().await;
                    }
                },
                async {
                    smol::Timer::after(Duration::from_secs(10)).await;
                    panic!("resized batch did not catch up");
                },
            ),
        )
        .await;
        assert_eq!(size.count, 2);
        let c = platform.0.lock().unwrap();
        assert_eq!(
            c.requests.iter().map(|r| r.max_blocks).collect::<Vec<_>>(),
            vec![8, 4, 2, 2, 2, 2, 2]
        );
    });
}
