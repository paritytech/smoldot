// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use super::{connection::*, discovery::*, reads::*, warp::*};
use crate::{
    AddChainConfig, AddChainConfigJsonRpc, Client, jam_webtransport_cert,
    platform::{self, MultiStreamAddress, SubstreamDirection},
};
use alloc::{borrow::Cow, collections::VecDeque};
use ark_vrf::{
    ietf::Prover as _, reexports::ark_serialize::CanonicalSerialize as _, suites::bandersnatch,
};
use core::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
};
use serde_json::{Value, json};
use smoldot::{
    jam::{
        codec,
        crypto::blake2b_256,
        finality::{self, Justification},
        metadata::ValidatorEndpoint,
        net,
        trie::{self, StateRequest, StateResponse, VerifiedRange},
        types::{BlockRequest, Direction, Final, Handshake, Hash, SealingSequence},
        verify::VerifiedHeader,
    },
    libp2p::read_write::ReadWrite,
};
use std::{collections::BTreeMap, sync::Mutex, time::Instant};

mod connection;
mod discovery;
mod grandpa;
mod reads;
mod rpc;
mod warp;

impl Default for StateReads {
    fn default() -> Self {
        Self::new(MAX_PEERS)
    }
}

/// A connection loop pinned to one peer, with its own reconnect backoff.
/// Scripted tests use it to drive a fixed peer on a chosen slot.
async fn peer_loop<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    peer: &Peer,
    peer_index: usize,
    params: &Params,
    state: Arc<async_lock::Mutex<State>>,
) {
    let mut backoff = 1;
    let mut fetch_size = FetchSize::default();
    let mut root_probe = None;
    loop {
        if state.lock().await.stopped {
            future::pending::<()>().await;
        }
        let Some(outcome) = connect_once(
            platform,
            log_name,
            peer,
            peer_index,
            params,
            &state,
            (&mut fetch_size, &mut root_probe),
            None,
        )
        .await
        else {
            return;
        };
        if outcome.stopped {
            continue;
        }
        if outcome.lasted >= Duration::from_secs(60) {
            backoff = 1;
        }
        log!(platform, Debug, log_name, "jam-reconnect");
        platform.sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

/// [`drive_connection`], discarding its end reason.
async fn drive<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    params: &Params,
    peer_index: usize,
    state: &Arc<async_lock::Mutex<State>>,
    transport: P::MultiStream,
    (fetch_size, root_probe): (&mut FetchSize, &mut Option<Hash>),
) {
    drive_connection(
        platform,
        log_name,
        params,
        peer_index,
        state,
        transport,
        (fetch_size, root_probe),
    )
    .await;
}

/// A root-only tree at a zeroed genesis with six zero keys and one-slot epochs.
fn root_config() -> Config {
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
    Config {
        tree: HeaderTree::new(
            params.clone(),
            verified_genesis(&params, header, state),
            tree::Config {
                max_blocks: NonZeroUsize::new(4).unwrap(),
                max_bytes: usize::MAX,
                max_epoch_records: NonZeroUsize::new(8).unwrap(),
            },
        )
        .unwrap(),
        authorities: AuthoritySet::from_checkpoint(&params, 0, vec![[0; 32]; 6], vec![[0; 32]; 6])
            .unwrap(),
        max_blocks: 4,
        tree_config: tree::Config {
            max_blocks: NonZeroUsize::new(4).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: NonZeroUsize::new(8).unwrap(),
        },
        params,
        peers: Vec::new(),
        genesis: Vec::new(),
        header_bytes: 4096,
    }
}

/// The driver state for `config`, as [`run`] builds it.
fn state(config: Config) -> State {
    State {
        reads: StateReads::default(),
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
        discovery: Discovery::new(Pool::new(Vec::new(), Vec::new(), 6)),
    }
}

/// [`root_config`]'s state, with two peers.
fn root_state() -> State {
    let mut state = state(root_config());
    state.peer_count = 2;
    state
}

/// `header` with the light state `post_state` after it, as if verified.
fn assume_verified(params: &Params, header: &Header, post_state: LightState) -> VerifiedHeader {
    VerifiedHeader::assume_verified(
        header.encode(params),
        header.parent,
        header.hash(params),
        header.slot,
        header.epoch_mark.is_some(),
        post_state,
    )
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
struct FakePlatform(Arc<Mutex<Control>>);

#[derive(Default)]
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
    state_responses: VecDeque<Result<Vec<u8>, Reset>>,
    state_requests: Vec<Vec<u8>>,
    params: Option<Params>,
    reject_batch_above: Option<u32>,
    proofs: BTreeMap<Hash, Vec<u8>>,
    warps: BTreeMap<u32, Vec<u8>>,
    warp_requests: Vec<u32>,
    bad_warp_once: bool,
    warp_resets: VecDeque<Reset>,
    /// The platform reports no reset codes, as Firefox does.
    codeless: bool,
    proof_resets: VecDeque<Reset>,
    block_resets: VecDeque<(Direction, Reset)>,
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
    /// Ports whose connections die at once, and every port dialed, in order.
    dead_ports: Vec<u16>,
    connected_ports: Vec<u16>,
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

/// A scripted stream reset: the peer's application error code, if the
/// platform reports one, and the platform's message.
#[derive(Clone, Copy, Debug)]
struct Reset(Option<u32>, &'static str);

impl core::fmt::Display for Reset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.1)
    }
}

impl Control {
    /// The next scripted CE 129 response. Discovery reads `C(8)` after
    /// finality advances; a test that did not script that read sees a peer
    /// without the state.
    fn state(&mut self, request: Vec<u8>) -> Result<Vec<u8>, Reset> {
        self.io.state_requests.push(request);
        let response = self.io.state_responses.pop_front();
        response.unwrap_or(Err(Reset(Some(6), "unscripted state read")))
    }

    /// The scripted CE 130 response for `target`.
    fn proof(&mut self, target: Hash) -> Result<Vec<u8>, Reset> {
        self.io.proof_requests.push(target);
        if let Some(reason) = self.io.proof_resets.pop_front() {
            return Err(reason);
        }
        let response = self.io.proofs.get(&target).cloned();
        response.ok_or(Reset(Some(6), "no justification"))
    }

    /// The scripted CE 153 response from set `start`.
    fn warp(&mut self, start: u32) -> Result<Vec<u8>, Reset> {
        self.io.warp_requests.push(start);
        if let Some(reason) = self.io.warp_resets.pop_front() {
            return Err(reason);
        }
        let response = self.io.warps.get(&start).cloned();
        let mut response = response.ok_or(Reset(Some(6), "no warp fragments"))?;
        if self.io.bad_warp_once {
            self.io.bad_warp_once = false;
            response[5] ^= 1; // Authenticated header parent, not the frame/count.
        }
        Ok(response)
    }

    /// The scripted CE 128 response to `request`.
    fn blocks(&mut self, request: BlockRequest) -> Result<Vec<u8>, Reset> {
        assert!((1..=64).contains(&request.max_blocks));
        let reset = self.io.block_resets.front();
        if reset.is_some_and(|(direction, _)| *direction == request.direction) {
            let (_, reason) = self.io.block_resets.pop_front().unwrap();
            self.requests.push(request);
            return Err(reason);
        }
        let mut payload = Vec::new();
        let mut hash = request.hash;
        for _ in 0..request.max_blocks.min(64) {
            let response = match request.direction {
                Direction::DescendingInclusive => self.responses.get_key_value(&hash),
                Direction::AscendingExclusive
                    if self
                        .io
                        .preferred_child
                        .is_some_and(|(parent, _)| parent == hash) =>
                {
                    let (_, child) = self.io.preferred_child.unwrap();
                    self.responses.get_key_value(&child)
                }
                Direction::AscendingExclusive => self
                    .responses
                    .iter()
                    .find(|(_, frame)| frame.get(4..36) == Some(hash.as_slice())),
            };
            let Some((next_hash, frame)) = response else {
                break;
            };
            payload.extend_from_slice(&frame[4..]);
            // A scripted response holding only a header gets an empty
            // extrinsic, as a CE 128 block carries both.
            if self
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
        let oversize = self
            .io
            .reject_batch_above
            .is_some_and(|limit| request.max_blocks > limit);
        self.requests.push(request);
        if payload.is_empty() {
            self.io.no_blocks += 1;
            return Err(Reset(Some(6), "no block"));
        }
        Ok(if oversize {
            u32::try_from(FRAME_BYTES + 1)
                .unwrap()
                .to_le_bytes()
                .to_vec()
        } else {
            framed(payload)
        })
    }
}

impl FakeStream {
    fn new(control: &Arc<Mutex<Control>>, now: Instant, incoming: VecDeque<u8>, ce: bool) -> Self {
        Self {
            control: control.clone(),
            rw: ReadWrite {
                now,
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
        }
    }
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
    type StreamErrorRef<'a> = Reset;
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
        // Event-driven tests must progress on readiness alone, not on the
        // driver's 100 ms watchdog poll. Other tests keep real timers to cover
        // deadlines and backoff.
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
        let MultiStreamAddress::WebTransport {
            cert_hashes, port, ..
        } = address
        else {
            panic!("not WebTransport")
        };
        let mut c = self.0.lock().unwrap();
        c.attempts += 1;
        c.io.live_connections += 1;
        c.pins.push(cert_hashes.into_owned());
        c.io.connected_ports.push(port);
        let dead = (c.fail_first && c.attempts == 1) || c.io.dead_ports.contains(&port);
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
        let stream = FakeStream::new(&connection.control, Instant::now(), incoming, ce);
        connection.streams.push_back(stream);
        if !ce && connection.control.lock().unwrap().starve {
            connection.control.lock().unwrap().io.live_streams += 3;
            for _ in 0..3 {
                let mut stream = FakeStream::new(&connection.control, self.now(), [].into(), false);
                stream.inbound = true;
                connection.streams.push_back(stream);
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
    fn read_write_access<'a>(&self, stream: Pin<&'a mut FakeStream>) -> Result<Access<'a>, Reset> {
        let stream = stream.get_mut();
        for buffer in stream.rw.write_buffers.drain(..) {
            stream.outgoing.extend(buffer);
        }
        stream.rw.write_bytes_queued = 0;
        if stream.rw.write_bytes_queueable.is_some() {
            stream.rw.write_bytes_queueable = Some(7);
        }
        if stream.ce && !stream.response_started && stream.rw.write_bytes_queueable.is_none() {
            let mut c = stream.control.lock().unwrap();
            let response = match stream.outgoing[0] {
                128 => c.blocks(BlockRequest::decode(&stream.outgoing[5..]).unwrap())?,
                129 => c.state(stream.outgoing[5..].to_vec())?,
                130 => c.proof(stream.outgoing[5..37].try_into().unwrap())?,
                153 => c.warp(u32::from_le_bytes(
                    stream.outgoing[5..9].try_into().unwrap(),
                ))?,
                kind => panic!("no scripted response for stream kind {kind}"),
            };
            drop(c);
            stream.incoming = response.into();
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
    fn stream_reset_code(&self, error: &Reset) -> Option<u32> {
        error.0.filter(|_| !self.0.lock().unwrap().io.codeless)
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

/// The certificate vectors, the synthetic chain, or a file of the library's
/// PolkaJam capture.
fn fixture(name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = match name {
        "cert_vector.json" => root.join("src/jam_webtransport_cert/fixtures").join(name),
        "synthetic.json" => root.join("src/sync_service/jam/fixtures").join(name),
        "polkajam-grandpa.json" => root.join("../lib/src/jam/finality/fixtures").join(name),
        _ => root.join("../lib/src/jam/fixtures/polkajam").join(name),
    };
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// Applies `change` to the metadata of every validator in the spec's genesis
/// `C(8)`, re-encoding the item.
fn edit_genesis_metadata(spec: &mut Value, change: impl Fn(&mut [u8; 128])) {
    let parsed = JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).unwrap();
    let key = hex::encode(smoldot::jam::codec::state_key(8));
    let mut validators = parsed.genesis_light_state().active_validators.clone();
    for validator in &mut validators {
        change(&mut validator.metadata);
    }
    spec["genesis_state"][&key] = json!(hex::encode(
        smoldot::jam::codec::encode_active_validators(&validators)
    ));
}

/// Removes the P-256 identity from every genesis validator (parity byte 4
/// means "no key"), so the spec's bootnodes are the only candidates.
fn without_genesis_p256(spec: &mut Value) {
    edit_genesis_metadata(spec, |metadata| metadata[18] = 4);
}

fn fixture_setup() -> (FakePlatform, String, Hash, Vec<u8>) {
    let mut spec = fixture("chain-spec.polkajam.json");
    let cert = fixture("cert_vector.json");
    let identity = cert[0]["p256_id_text"].as_str().unwrap();
    spec["bootnodes_p256"] = json!([alloc::format!("{identity}@127.0.0.1:4433")]);
    // These scripted tests drive the one bootnode; genesis seeding has its own tests.
    without_genesis_p256(&mut spec);
    let up = fixture("messages/up0.json");
    let ce = fixture("messages/ce128.json");
    let mut handshake = bytes(&up["handshake_frame_hex"]);
    handshake.extend(bytes(&up["announcement_frame_hex"]));
    let request = BlockRequest::decode(&bytes(&ce["request_frame_hex"])[4..]).unwrap();
    let response = bytes(&ce["response_frame_hex"]);
    let encoded = bytes(&fixture("headers/0000.json")["header_hex"]);
    let platform = platform(Control {
        handshake,
        responses: [(request.hash, response)].into(),
        supported: true,
        ..Control::default()
    });
    let spec = spec.to_string();
    platform.0.lock().unwrap().io.params = Some(parse(&spec).params().clone());
    (platform, spec, request.hash, encoded)
}

fn platform(control: Control) -> FakePlatform {
    FakePlatform(Arc::new(Mutex::new(control)))
}

fn parse(spec: &str) -> JamChainSpec {
    JamChainSpec::from_json_bytes(spec.as_bytes()).unwrap()
}

/// `0x`-prefixed hex, as the JSON-RPC API writes hashes and headers.
fn prefixed(bytes: impl AsRef<[u8]>) -> String {
    alloc::format!("0x{}", hex::encode(bytes))
}

fn final_of(params: &Params, header: &Header) -> Final {
    Final {
        hash: header.hash(params),
        slot: header.slot,
    }
}

fn handshake_frame(final_: Final, leaves: Vec<Final>) -> Vec<u8> {
    framed(Handshake { final_, leaves }.encode())
}

fn announcement_frame(params: &Params, header: Header, final_: Final) -> Vec<u8> {
    framed(smoldot::jam::types::Announcement { header, final_ }.encode(params))
}

/// Serves `header` with an empty extrinsic over CE 128.
fn serve(c: &mut Control, params: &Params, header: &Header) {
    let mut block = header.encode(params);
    block.extend([0; 7]); // Five components; disputes has three lists.
    c.responses.insert(header.hash(params), framed(block));
}

/// Runs `future`, failing with `what` after `secs` seconds.
async fn within<T>(secs: u64, what: &str, future: impl Future<Output = T>) -> T {
    future::or(future, async {
        smol::Timer::after(Duration::from_secs(secs)).await;
        panic!("{what} timed out")
    })
    .await
}

/// Runs `scenario` within `secs` seconds while `driver` runs, failing with
/// `what` if the driver ends first.
async fn while_driving<T>(
    secs: u64,
    what: &str,
    driver: impl Future<Output = ()>,
    scenario: impl Future<Output = T>,
) -> T {
    let driver = async {
        driver.await;
        panic!("{what}: the driver ended")
    };
    within(secs, what, future::or(driver, scenario)).await
}

/// Yields until `condition` holds.
async fn yield_until(mut condition: impl AsyncFnMut() -> bool) {
    while !condition().await {
        future::yield_now().await;
    }
}

/// A GRANDPA signing key, and its public key.
async fn grandpa_key(seed: u8) -> (ed25519_zebra::SigningKey, [u8; 32]) {
    let key = ed25519_zebra::SigningKey::from([seed; 32]);
    let public = ed25519_zebra::VerificationKey::from(&key).into();
    (key, public)
}

/// A Bandersnatch secret for sealing headers, and its public key.
fn bandersnatch_key(seed: &[u8]) -> (bandersnatch::Secret, [u8; 32]) {
    let secret = bandersnatch::Secret::from_seed(seed);
    let mut public = [0; 32];
    secret
        .public()
        .serialize_compressed(&mut public[..])
        .unwrap();
    (secret, public)
}

/// An IETF VRF signature: the output point, then the proof.
fn vrf_sign(secret: &bandersnatch::Secret, context: &[u8], aux: &[u8]) -> [u8; 96] {
    let input = bandersnatch::Input::new(context).unwrap();
    let output = secret.output(input);
    let mut signature = [0; 96];
    output.serialize_compressed(&mut signature[..32]).unwrap();
    (secret.prove(input, output, aux))
        .serialize_compressed(&mut signature[32..])
        .unwrap();
    signature
}

/// Seals `header` on `parent` as author 0 with `secret`, which must hold the
/// fallback key of every slot of the header's epoch.
fn seal_fallback(
    params: &Params,
    parent: &VerifiedHeader,
    mut header: Header,
    secret: &bandersnatch::Secret,
) -> Header {
    let state = parent.post_state();
    // An epoch change rotates `η2` into `η3`.
    let epoch_changed = header.slot / params.epoch_len > state.slot() / params.epoch_len;
    let eta3 = state.entropy()[if epoch_changed { 2 } else { 3 }];
    let context = [b"jam_fallback_seal".as_slice(), &eta3].concat();
    let input = bandersnatch::Input::new(&context).unwrap();
    let seal_output = &secret.output(input).hash()[..32];
    header.author_index = 0;
    let entropy_context = [b"jam_entropy".as_slice(), seal_output].concat();
    header.entropy_source = vrf_sign(secret, &entropy_context, &[]);
    header.seal = vrf_sign(secret, &context, &header.encode_unsigned(params));
    header
}

/// A justification for `commit` with one precommit by `public`, signed over
/// `root` as the posterior state root. The vote names the last of
/// `witnesses`, which link it back to `commit`, or `commit` itself.
async fn single_vote_justification(
    (key, public): (&ed25519_zebra::SigningKey, [u8; 32]),
    (round, set_id): (u64, u32),
    (commit, root): (Final, Hash),
    witnesses: &[Header],
    params: &Params,
) -> Vec<u8> {
    let vote = witnesses
        .last()
        .map_or(commit.clone(), |h| final_of(params, h));
    let target = |f: &Final| [&f.hash[..], &root, &f.slot.to_le_bytes()].concat();
    let round_and_set = [round.to_le_bytes().as_slice(), &set_id.to_le_bytes()].concat();
    let payload = [
        b"jam_grandpa_vote\x01".as_slice(),
        &target(&vote),
        &round_and_set,
    ]
    .concat();
    let signature: [u8; 64] = key.sign(&payload).into();
    let mut proof = [round_and_set, target(&commit), codec::encode_natural(1)].concat();
    proof.extend([target(&vote), signature.to_vec(), public.to_vec()].concat());
    proof.extend(codec::encode_natural(witnesses.len().try_into().unwrap()));
    for header in witnesses {
        proof.extend(header.encode(params));
    }
    proof
}

/// Dials one scripted peer and drives that connection as `peer`.
async fn drive_peer(
    platform: &FakePlatform,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
    peer: usize,
    (fetch_size, probe): (&mut FetchSize, &mut Option<Hash>),
) {
    let address = MultiStreamAddress::WebTransport {
        ip: "127.0.0.1".parse().unwrap(),
        port: 4433,
        cert_hashes: Cow::Owned(vec![[1; 32]; 3]),
    };
    let connected = platform.connect_multistream(address).await;
    let transport = connected.connection;
    let budget = (fetch_size, probe);
    drive(platform, "scripted", params, peer, state, transport, budget).await;
}

/// A connection to the scripted peer, without dialing.
fn fake_connection(platform: &FakePlatform) -> FakeConnection {
    platform.0.lock().unwrap().io.live_connections += 1;
    FakeConnection {
        control: platform.0.clone(),
        streams: VecDeque::new(),
        number: 0,
        dead: false,
    }
}

/// A one-leaf trie holding `C(8) = value`: its root and the CE 129 response.
fn active_set_trie(value: &[u8]) -> (Hash, Vec<u8>) {
    let key = trie::state_key(8);
    let mut node = [0; 64];
    node[0] = 0xc0;
    node[1..32].copy_from_slice(&key);
    node[32..].copy_from_slice(&blake2b_256(value));
    let mut entries = key.to_vec();
    entries.extend(codec::encode_natural(u64::try_from(value.len()).unwrap()));
    entries.extend(value);
    let mut response = framed(node.to_vec());
    response.extend(framed(entries));
    (blake2b_256(&node), response)
}

fn add_chain(
    client: &mut Client<FakePlatform>,
    specification: &str,
    json_rpc: bool,
) -> Result<crate::AddChainSuccess<FakePlatform>, crate::AddChainError> {
    client.add_chain(AddChainConfig {
        specification,
        user_data: (),
        database_content: "",
        potential_relay_chains: core::iter::empty(),
        json_rpc: if json_rpc {
            AddChainConfigJsonRpc::Enabled {
                max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
                max_subscriptions: 2,
            }
        } else {
            AddChainConfigJsonRpc::Disabled
        },
        max_pending_transactions: core::num::NonZeroU32::new(64).unwrap(),
        statement_protocol_config: None,
    })
}

fn sync_service(platform: &FakePlatform, spec: &JamChainSpec) -> JamSyncService {
    let config = Config::from_spec(spec).unwrap();
    JamSyncService::new(platform.clone(), "jam-test".into(), config)
}

/// The next notification, within ten seconds.
async fn received(what: &str, rx: &async_channel::Receiver<Notification>) -> Notification {
    within(10, what, rx.recv()).await.unwrap()
}

fn framed(payload: Vec<u8>) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    frame.extend(payload);
    frame
}

/// Polls `condition` every millisecond until it holds.
async fn until(mut condition: impl FnMut() -> bool) {
    within(10, "condition", async {
        while !condition() {
            smol::Timer::after(Duration::from_millis(1)).await;
        }
    })
    .await;
}

fn rejected_add_chain_without_startup(platform: &FakePlatform, specification: &str) -> ConfigError {
    let mut client = Client::new(platform.clone());
    let error = match add_chain(&mut client, specification, true) {
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

/// The shortest header bytes the JSON-RPC service accepts: zeros up to the slot.
fn header_bytes(slot: u32) -> Vec<u8> {
    let mut bytes = vec![0; 96];
    bytes.extend(slot.to_le_bytes());
    bytes
}

/// The header with slot `header` on the header with slot `parent`.
fn notification(header: u8, parent: u8, is_new_best: bool) -> BlockNotification {
    BlockNotification {
        is_new_best,
        scale_encoded_header: header_bytes(header.into()),
        parent_hash: blake2b_256(&header_bytes(parent.into())),
    }
}

/// Runs `scenario` on a single-threaded executor that also runs the fake
/// platform's tasks, as in a browser.
fn event_driven<F: Future<Output = ()> + Send + 'static>(
    scenario: impl FnOnce(Arc<smol::Executor<'static>>) -> F,
) {
    let executor = Arc::new(smol::Executor::new());
    let task = executor.spawn(scenario(executor.clone()));
    smol::block_on(executor.run(task));
}

fn synthetic_driver(blocks: usize, capacity: usize) -> (FakePlatform, Config, Vec<Header>) {
    let corpus = fixture("synthetic.json");
    let (platform, boot_spec, _, _) = fixture_setup();
    let mut spec = corpus["spec"].clone();
    spec["bootnodes_p256"] =
        serde_json::from_str::<Value>(&boot_spec).unwrap()["bootnodes_p256"].clone();
    let mut config = Config::from_spec(&parse(&spec.to_string())).unwrap();
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
            serve(&mut c, &config.params, header);
        }
        c.handshake = handshake_frame(final_of(&config.params, tip), vec![]);
        for (hash, proof) in corpus["proofs"].as_object().unwrap() {
            c.io.proofs.insert(
                hex::decode(hash).unwrap().try_into().unwrap(),
                framed(bytes(proof)),
            );
        }
    }
    (platform, config, headers)
}

/// The proof of a framed CE 129 response.
fn state_response(frame: &[u8]) -> StateResponse {
    let n = usize::try_from(u32::from_le_bytes(frame[..4].try_into().unwrap())).unwrap();
    let limits = trie::ResponseLimits {
        max_nodes: 496,
        max_entries: 32768,
        max_value_bytes: FRAME_BYTES,
        max_total_bytes: FRAME_BYTES + 496 * 64,
    };
    StateResponse::decode(&frame[4..4 + n], &frame[8 + n..], &limits).unwrap()
}

/// [`drive_peer`] from one-block batches that may grow to `ceiling`, with no
/// root probe.
async fn drive_scripted(
    platform: &FakePlatform,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
    peer: usize,
    ceiling: u32,
) {
    let mut fetch = FetchSize { count: 1, ceiling };
    drive_peer(platform, params, state, peer, (&mut fetch, &mut None)).await;
}

/// The fields of each `message` the platform logged.
fn logged(platform: &FakePlatform, message: &str) -> Vec<BTreeMap<String, String>> {
    let c = platform.0.lock().unwrap();
    let logs = c.io.log_fields.iter().filter(|(m, _)| m == message);
    logs.map(|(_, fields)| fields.clone()).collect()
}

fn driver_state(config: Config) -> Arc<async_lock::Mutex<State>> {
    Arc::new(async_lock::Mutex::new(state(config)))
}
