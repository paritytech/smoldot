// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Header-only JAM synchronization with verified GRANDPA root advancement.
//!
//! Resource accounting (estimates, not a process/allocator peak measurement):
//! the tree and its verification/rebuild copies share 16 MiB. Reserve one
//! worst-case header and epoch state for verification, then halve the remainder
//! for retained storage and the survivor rebuild (shared epochs aren't copied).
//! The byte-accounted tree preallocates its bounded slab, counts shared epoch
//! and ticket allocations once, and permits at most eight epoch records and
//! 4096 headers. Each of two peers
//! retains at most eight repair headers and eight announcements (at most
//! 8 MiB together at the maximum accepted header budget). Allow 16 MiB per peer
//! for B2 frames, decoded events and bounded I/O staging, including one decoded
//! CE128 batch capped at 1 MiB of wire bytes (owned header allocations are
//! bounded by their wire lengths and Params). Adaptive requests grow from one
//! to 64 blocks within that cap. Eight subscriber queues add at most 1 MiB each.
//! Another 4 MiB covers the single shared proof, decoded witnesses, verifier
//! scratch space, current/next authorities and transition copies. At most 4096
//! attempted-target records, including vector growth slack, fit in 512 KiB.
//! State reads share the two pending CE slots with blocks and finality proofs.
//! One shared read retains at most 1 MiB of entries and 31 KiB of boundary nodes plus its verified
//! copy; allow another 4 MiB for entry metadata, proof indexing and frame staging.
//! Warp adds one 8-MiB CE153 frame, its bounded decoded fragments, one join
//! header (the finalized head, whose state is read against the posterior root
//! its justification signs) and four bounded state values. Only the reserved
//! peer can warp; allow 24 MiB for that transient phase (approximately 105 MiB
//! total).
//! CE128 block budget: `FRAME_BYTES` stays 1 MiB per response. PolkaJam
//! `27d63b8d` (PR #1284) allows a block of header and extrinsic maxima plus a
//! 32 MiB preimage and serves responses up to four times that. Measured on the
//! dev network at that pin (2026-10-04, 205 blocks, 20 minutes): largest block
//! 2,659 bytes, largest header 746 bytes, none near 256 KiB. A block above the
//! budget cannot be fetched, which stalls the join and ascending sync at that
//! block until D16 (light blocks over CE 128); the budget is deliberately not
//! raised to the theoretical maximum.
//! One RPC frontend separately allows two 4 MiB pin maps, a temporary snapshot
//! below 8 MiB, 16 responses (each below about 1 MiB), and 32 64-KiB requests:
//! allow another 36 MiB including collection/staging overhead. The two pin maps
//! keep their independent 4-MiB byte limits even with 4096 retained headers.
//! Their 512-pin count budget applies to pinned blocks that are finalized or
//! pruned; non-finalized pins are bounded by the tree and the 4-MiB byte cap.
//! Additional
//! frontends cost additional memory; these are not a global client limit.
//! Platform-owned transport buffers, allocator metadata, executable/VM memory
//! and the bounded 16-MiB chain-spec parsing input are outside these estimates.
//! The external fixture test reports retained inline/vector-capacity bytes;
//! it deliberately does not label this as a measured total heap peak.
//! The peer pool holds at most 16 bootnodes and `max_validators` (at most 1023)
//! genesis or discovered candidates of under 200 bytes each, below 256 KiB.
//! The chain spec's bootnodes and its genesis `C(8)` both seed the pool; the
//! first verified `C(8)` read replaces the genesis entries. A `C(8)`
//! refresh is an ordinary state read through the shared slot; its decoded keys
//! (336 bytes per validator) live only while the pool is merged.

use super::{BlockNotification, Notification, SubscribeAll, SyncStatus, ToBackground};
use crate::{
    jam_webtransport_cert::{self, P256PeerId},
    log,
    platform::{MultiStreamAddress, PlatformRef, SubstreamDirection},
};
use alloc::{borrow::Cow, boxed::Box, collections::VecDeque, string::String, sync::Arc, vec::Vec};
use core::{
    fmt,
    num::NonZeroUsize,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use discovery::{Acquire, Peer, Pool, Release, Source};
use futures_lite::{StreamExt as _, future};
use smoldot::jam::{
    chain_spec::JamChainSpec,
    finality::{self, AuthoritySet, Justification},
    metadata::{self, ValidatorEndpoint},
    net,
    params::Params,
    state::LightState,
    tree::{self, HeaderTree},
    trie::{self, StateRequest, StateResponse, VerifiedRange},
    types::{BlockRequest, Direction, Final, GenesisLightState, Handshake, Hash, Header},
    verify::verified_genesis,
};

const TREE_BYTES: usize = 16 * 1024 * 1024;
const FRAME_BYTES: usize = 1024 * 1024;
const WARP_BYTES: usize = 8 * 1024 * 1024;
const REPAIR_LIMIT: usize = 8;
const MAX_SUBSCRIBERS: usize = 8;
const MAX_PEERS: usize = 2;
const TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Upper bound on a `C(8)` read response; the value is at most 343,731 bytes.
const ACTIVE_SET_READ_BYTES: u32 = 800_000;
/// An idle slot re-checks the pool at least this often.
const POOL_POLL: Duration = Duration::from_millis(500);
/// A slot on a discovered peer checks this often whether a bootnode is due.
const PREEMPT_POLL: Duration = Duration::from_secs(1);

// Debug events.
//
// Every log line of this driver is one event in one grammar, so a page or a
// test can parse it without knowing the code:
//
//     jam-<area>-<what>[; key=value, key=value, ...]
//
// The areas are `pool`, `peer` (with the older `slot`, `connect`,
// `reconnect` and `stream`), `block` (with `announcement` and `header`),
// `justification`, `state`, `warp` (with `anchor`), `finality` (with
// `finalized`) and `discovery`. Events are logged at Debug, except
// `jam-anchor-unserved` at Warn.
//
// Values are tokens: decimal numbers, `0x` hashes in full, `true`/`false`,
// addresses `ip:port`, this driver's own kebab-case words (`purpose`,
// `outcome`, `reason`), and error variant names (`NoData`,
// `Decode(LengthLimit)`; see [`Token`]). A value never contains `, ` or `=`,
// with two exceptions: `message=` of `jam-stream-reset` is the platform's
// free text and always the last field, so a parser takes the rest of the line
// after it verbatim; and `hash=` of `jam-anchor-unserved` (Warn) is a byte
// list, so a part without `key=` continues the previous value. `-` means that
// the field does not apply.
//
// Common fields:
//
// - `slot=` is the connection slot (0 or 1) on every line about one
//   connection, except five older lines whose `slot=` was already a block
//   slot and stays one for their consumers: `jam-warp-join-selected`,
//   `jam-warp-applied`, `jam-finalized`, `jam-anchor-unserved` and
//   `jam-discovery-read-started`. The first three carry the connection slot
//   as `conn=`. `jam-connect` and `jam-reconnect` carry no field at all,
//   because their consumers match them exactly; the `jam-slot-assigned` before
//   and the `jam-peer-disconnected` before them name the slot.
// - `req=` names one request for the whole client run: the start line
//   (`jam-<area>-request-queued`) and the outcome line
//   (`jam-<area>-request-ended`) share it, and so do the lines about that
//   request in between (`jam-stream-reset`, `jam-warp-rejected`,
//   `jam-finalized`, ...).
// - An outcome line carries `outcome=` (`ok`, `failed`, `rejected`,
//   `timeout`, `cancelled`) and `elapsed_ms=` since the request was queued.
//   `failed` adds the transport's `error=`, `rejected` the verifier's
//   `error=`, `timeout` and `cancelled` the connection's end `reason=`.
//   A request in flight when the pool moves its slot to a bootnode
//   (`jam-slot-preempted`) gets no outcome line; `jam-peer-disconnected` with
//   `reason=preempted` ends it.
// - `jam-peer-disconnected` carries `reason=`, one [`End`] per way a
//   connection ends.
//
// The table of every event is in `wasm-node/javascript/demo/jam.md`, section
// "Client events"; `demo/jam-events.mjs` is the page's parser.

/// The counter behind `req=`: unique within the process, hence within one
/// client run (each browser client is its own WASM instance).
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

fn next_request() -> u64 {
    NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
}

/// A request's log identity: its `req=` and what it is for.
#[derive(Clone, Copy)]
struct Tag {
    req: u64,
    purpose: &'static str,
}

impl Tag {
    fn new(purpose: &'static str) -> Self {
        Self {
            req: next_request(),
            purpose,
        }
    }
}

/// `0x` and the bytes in lowercase hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The value, or `-` when the field does not apply.
struct Opt<T>(Option<T>);

impl<T: fmt::Display> fmt::Display for Opt<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => value.fmt(f),
            None => f.write_str("-"),
        }
    }
}

/// An error's variant path as one token: its `Debug` output without
/// whitespace and without the fields of struct variants, for example
/// `Decode(LengthLimit)` or `WrongSetId`.
struct Token<'a>(&'a dyn fmt::Debug);

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Filter<'a, 'b> {
            out: &'a mut fmt::Formatter<'b>,
            depth: usize,
        }
        impl fmt::Write for Filter<'_, '_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                for c in text.chars() {
                    match c {
                        '{' => self.depth += 1,
                        '}' => self.depth = self.depth.saturating_sub(1),
                        _ if self.depth > 0 || c.is_whitespace() => {}
                        '=' => self.out.write_char(':')?,
                        c => self.out.write_char(c)?,
                    }
                }
                Ok(())
            }
        }
        fmt::write(
            &mut Filter { out: f, depth: 0 },
            format_args!("{:?}", self.0),
        )
    }
}

/// [`Token`] of a warp error, unwrapped like its `Display`.
fn warp_token(error: &WarpError) -> Token<'_> {
    match error {
        WarpError::Finality(error) => Token(error),
        WarpError::State(error) => Token(error),
        WarpError::Tree(error) => Token(error),
        other => Token(other),
    }
}

/// `C<n>` for the state key of item `n`, else the key in hex.
struct Key<'a>(&'a trie::StateKey);

impl fmt::Display for Key<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self.0 == trie::state_key(self.0[0]) {
            write!(f, "C{}", self.0[0])
        } else {
            Hex(self.0).fmt(f)
        }
    }
}

/// A state request's key range: `C8`, or `C4..C11`.
struct Keys<'a>(&'a StateRequest);

impl fmt::Display for Keys<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.start == self.0.end {
            Key(&self.0.start).fmt(f)
        } else {
            write!(f, "{}..{}", Key(&self.0.start), Key(&self.0.end))
        }
    }
}

fn direction_str(direction: &Direction) -> &'static str {
    match direction {
        Direction::AscendingExclusive => "ascending",
        Direction::DescendingInclusive => "descending",
    }
}

fn trust_str(trust: Trust) -> &'static str {
    match trust {
        Trust::Finalized => "finalized",
        Trust::Authenticated => "authenticated",
    }
}

/// What a state read is for: the warp join reads against a finalized root,
/// the `C(8)` refresh against an authenticated child's prior root.
fn read_purpose(trust: Trust) -> &'static str {
    match trust {
        Trust::Finalized => "warp-join",
        Trust::Authenticated => "discovery",
    }
}

/// Wire size of a CE 129 response: proof nodes, keys and values.
fn state_response_bytes(response: &StateResponse) -> usize {
    response.nodes.len() * 64
        + response
            .entries
            .iter()
            .map(|(_, value)| 31 + value.len())
            .sum::<usize>()
}

/// Why a connection ended: the `reason=` of `jam-peer-disconnected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// The transport did not connect within [`TIMEOUT`].
    ConnectTimeout,
    /// The JAMNP-S state machine refused its limits.
    Setup,
    /// The chain stopped (tree full or anchor unserved).
    Stopped,
    /// Another slot applied a warp join; every connection restarts on it.
    WarpRevision,
    HandshakeTimeout,
    /// Nothing was read for [`IDLE_TIMEOUT`].
    Idle,
    StreamOpenTimeout,
    StateTimeout,
    BlockTimeout,
    JustificationTimeout,
    WarpTimeout,
    /// A request or peer stream outlived [`TIMEOUT`].
    StreamTimeout,
    /// The peer reset a stream that carries no request (UP0), or the
    /// justification stream of a warp join.
    StreamReset,
    /// The platform closed the connection.
    Transport,
    /// A frame, buffer, header or counter bound.
    Limit,
    UnexpectedResponse,
    StateRejected,
    StateFailed,
    StateUnavailable,
    StateCancelled,
    BlockFailed,
    JustificationFailed,
    WarpFailed,
    WarpRejected,
    /// The warp join's own consistency checks failed.
    WarpInvalid,
    FinalityRejected,
    /// The peer answered `NoData` for our finalized root.
    RootRefused,
    /// The peer cannot extend our finalized root.
    RootUnextendable,
    AnchorUnserved,
    MessageTooLarge,
    ProtocolError,
    /// The connection refused to queue a request.
    RequestRefused,
    InsertFailed,
    TreeFull,
    /// The pool moved the slot to a bootnode whose retry was due.
    Preempted,
}

impl End {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConnectTimeout => "connect-timeout",
            Self::Setup => "setup",
            Self::Stopped => "stopped",
            Self::WarpRevision => "warp-revision",
            Self::HandshakeTimeout => "handshake-timeout",
            Self::Idle => "idle",
            Self::StreamOpenTimeout => "stream-open-timeout",
            Self::StateTimeout => "state-timeout",
            Self::BlockTimeout => "block-timeout",
            Self::JustificationTimeout => "justification-timeout",
            Self::WarpTimeout => "warp-timeout",
            Self::StreamTimeout => "stream-timeout",
            Self::StreamReset => "stream-reset",
            Self::Transport => "transport",
            Self::Limit => "limit",
            Self::UnexpectedResponse => "unexpected-response",
            Self::StateRejected => "state-rejected",
            Self::StateFailed => "state-failed",
            Self::StateUnavailable => "state-unavailable",
            Self::StateCancelled => "state-cancelled",
            Self::BlockFailed => "block-failed",
            Self::JustificationFailed => "justification-failed",
            Self::WarpFailed => "warp-failed",
            Self::WarpRejected => "warp-rejected",
            Self::WarpInvalid => "warp-invalid",
            Self::FinalityRejected => "finality-rejected",
            Self::RootRefused => "root-refused",
            Self::RootUnextendable => "root-unextendable",
            Self::AnchorUnserved => "anchor-unserved",
            Self::MessageTooLarge => "message-too-large",
            Self::ProtocolError => "protocol-error",
            Self::RequestRefused => "request-refused",
            Self::InsertFailed => "insert-failed",
            Self::TreeFull => "tree-full",
            Self::Preempted => "preempted",
        }
    }
}

pub(crate) struct Config {
    params: Params,
    tree: HeaderTree,
    /// The chain spec's bootnodes with a P-256 identity.
    peers: Vec<Peer>,
    /// The genesis `C(8)` validators with a P-256 identity and a port: the
    /// pool's initial discovered set.
    genesis: Vec<Peer>,
    header_bytes: usize,
    authorities: AuthoritySet,
    max_blocks: usize,
    tree_config: tree::Config,
}

impl Config {
    pub(crate) fn from_spec(spec: &JamChainSpec) -> Result<Self, String> {
        let params = spec.params().clone();
        let (header_bytes, limits) = memory_limits(&params)?;
        let max_blocks = limits.max_blocks;
        let (header, raw_state) = spec.checkpoint().map_or(
            (spec.genesis_header(), spec.genesis_light_state()),
            |checkpoint| (&checkpoint.header, &checkpoint.state),
        );
        let state = Self::anchor_state(&params, raw_state)?;
        let authorities = match spec.checkpoint() {
            Some(checkpoint) => checkpoint.finality.clone(),
            None => AuthoritySet::from_genesis(&params, header)
                .map_err(|e| alloc::format!("JAM genesis finality: {e}"))?,
        };
        let mut peers: Vec<Peer> = Vec::new();
        for node in spec.boot_nodes() {
            if let Some(p256_id_text) = node.p256_id_text {
                let identity = P256PeerId::from_text(&p256_id_text)
                    .map_err(|e| alloc::format!("JAM P256 identity: {e:?}"))?;
                if peers.len() < discovery::MAX_BOOTNODES
                    && !peers.iter().any(|peer| peer.ed25519 == node.ed25519)
                {
                    peers.push(Peer {
                        identity,
                        ip: node.ip,
                        port: node.port,
                        ed25519: node.ed25519,
                        source: Source::Bootnode,
                    });
                }
            }
        }
        // Liveness sources only, like bootnodes: whatever they serve is verified
        // the same way. Records whose key is not a curve point are skipped.
        let genesis: Vec<Peer> = spec
            .genesis_validators()
            .filter_map(|endpoint| Peer::discovered(&endpoint))
            .map(|peer| Peer {
                source: Source::Genesis,
                ..peer
            })
            .collect();
        if peers.is_empty() && genesis.is_empty() {
            return Err(String::from(
                "JAM chain spec has no dialable peer: no bootnode has a valid P-256 identity \
                 and no validator in the genesis C(8) advertises a valid one with a port",
            ));
        }
        let root = verified_genesis(&params, header.clone(), state);
        let tree = HeaderTree::new(params.clone(), root, limits)
            .map_err(|_| String::from("JAM trusted anchor exceeds tree budget"))?;
        Ok(Self {
            params,
            tree,
            peers,
            genesis,
            authorities,
            max_blocks: max_blocks.get(),
            header_bytes,
            tree_config: limits,
        })
    }

    fn anchor_state(params: &Params, raw_state: &GenesisLightState) -> Result<LightState, String> {
        let state = LightState::from_anchor(params, raw_state)
            .map_err(|e| alloc::format!("JAM starting state: {e:?}"))?;
        state
            .validate(params)
            .map_err(|e| alloc::format!("JAM starting state: {e:?}"))?;
        Ok(state)
    }
}

fn memory_limits(params: &Params) -> Result<(usize, tree::Config), String> {
    // Worst-case owned header and post-state allocations, including vector capacity
    // slack. Two complete trees cover B4's transient survivor cloning on eviction.
    let validators = usize::from(params.max_validators);
    let epoch =
        usize::try_from(params.epoch_len).map_err(|_| String::from("JAM epoch too large"))?;
    let header_bytes = epoch
        .checked_mul(80)
        .and_then(|n| n.checked_add(validators * 192 + 2048))
        .ok_or_else(|| String::from("JAM header budget overflow"))?;
    let state_bytes = epoch
        .checked_mul(160)
        .and_then(|n| n.checked_add(validators * 256 + 2048))
        .ok_or_else(|| String::from("JAM state budget overflow"))?;
    if header_bytes > FRAME_BYTES / 2 || state_bytes > TREE_BYTES / 8 {
        return Err(String::from("JAM trusted parameters exceed memory budget"));
    }
    // Reserve one worst-case epoch/state and header for verification; keep the
    // second-tree allowance while eviction rebuilds survivors.
    let max_bytes = (TREE_BYTES - header_bytes - state_bytes) / 2;
    let max_blocks = (max_bytes / (HeaderTree::node_overhead() + 297)).min(4096);
    let max_blocks = NonZeroUsize::new(max_blocks)
        .filter(|n| n.get() >= 2)
        .ok_or_else(|| String::from("JAM tree budget too small"))?;
    Ok((
        header_bytes,
        tree::Config {
            max_blocks,
            max_bytes,
            max_epoch_records: NonZeroUsize::new(8)
                .ok_or_else(|| String::from("JAM record limit is zero"))?,
        },
    ))
}

struct State {
    reads: StateReads,
    #[cfg(test)]
    test_verifier: Option<
        fn(
            &Params,
            &smoldot::jam::verify::VerifiedHeader,
            Header,
        ) -> smoldot::jam::verify::VerifiedHeader,
    >,
    tree: HeaderTree,
    params: Params,
    subscribers: Vec<async_channel::Sender<Notification>>,
    stopped: bool,
    header_bytes: usize,
    authorities: AuthoritySet,
    max_blocks: usize,
    /// A single shared proof reservation, deduplicated across peer drivers.
    proof_owner: Option<(usize, Hash)>,
    /// Attempted configured peers per retained target. Never grows beyond the tree.
    proof_attempts: Vec<(Hash, u8)>,
    tree_config: tree::Config,
    warp_owner: Option<usize>,
    warp_revision: u64,
    /// Refusals apply only to this exact finalized root, by distinct peers.
    root_refusals: Option<(Hash, u8)>,
    peer_count: usize,
    discovery: Discovery,
}

/// The peer pool and the `C(8)` refresh that feeds it.
struct Discovery {
    pool: Pool,
    /// The active set has not been read since the last finalized epoch change.
    stale: bool,
    /// A finality advance happened while stale; read when the slot is free.
    due: bool,
    read: Option<DiscoveryRead>,
}

struct DiscoveryRead {
    expected: StateRead,
    rx: futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>,
    started_ms: u128,
}

impl Discovery {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            stale: true,
            due: false,
            read: None,
        }
    }
}

/// What a discovery turn did, for the driver's log.
#[derive(Debug, PartialEq, Eq)]
enum DiscoveryEvent {
    Started {
        slot: u32,
    },
    Refreshed {
        merge: discovery::Merge,
        value_bytes: usize,
        elapsed_ms: u128,
    },
    Failed {
        reason: &'static str,
    },
}

#[derive(Debug)]
enum WarpError {
    Finality(finality::Error),
    State(smoldot::jam::state::StateError),
    Tree(tree::InsertError),
    InvalidJoin,
    StaleAnchor,
    ResourceLimit,
}

/// Terminal availability failure, scoped to the exact authenticated anchor.
#[derive(Debug, PartialEq, Eq)]
struct AnchorUnserved {
    hash: Hash,
    slot: u32,
}

impl core::fmt::Display for AnchorUnserved {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "anchor {:?} at slot {} is unserved",
            self.hash, self.slot
        )
    }
}

impl core::error::Error for AnchorUnserved {}

impl core::fmt::Display for WarpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Finality(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Tree(e) => write!(f, "{e:?}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// Staged authorities and state never affect the live tree until the finalized
/// head's justification and the state proofs against its signed root succeed.
struct Warp {
    anchor: Hash,
    authorities: AuthoritySet,
    last_slot: u32,
    /// Exact target already finalized and rotated by the last verified fragment.
    last_final: Option<finality::Target>,
    fragments: usize,
    chain_done: bool,
    final_head: Option<Final>,
    /// The frozen finalized head F, fetched as one descending block.
    head: Option<Header>,
    /// F's verified GRANDPA target: its `state_root` is the signed posterior root
    /// the join reads against. `None` until F is authenticated.
    finalized: Option<finality::Target>,
    state_responses: usize,
    items: Vec<(trie::StateKey, Vec<u8>)>,
    read: Option<futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>>,
}

impl Warp {
    fn new(state: &State) -> Self {
        Self {
            anchor: state.tree.finalized().hash,
            authorities: state.authorities.clone(),
            last_slot: state.tree.finalized().slot,
            last_final: None,
            fragments: 0,
            chain_done: false,
            final_head: None,
            head: None,
            finalized: None,
            state_responses: 0,
            items: Vec::new(),
            read: None,
        }
    }

    fn advance(
        &mut self,
        params: &Params,
        bytes: &[u8],
        limits: &finality::WarpLimits,
    ) -> Result<(), WarpError> {
        let fragments =
            finality::decode_warp_response(params, bytes, limits).map_err(WarpError::Finality)?;
        self.chain_done = fragments.len() < 32;
        for fragment in fragments {
            if params.epoch_len == 0
                || fragment.header.slot / params.epoch_len <= self.last_slot / params.epoch_len
            {
                return Err(WarpError::InvalidJoin);
            }
            let (authorities, target) = self
                .authorities
                .advance_warp(params, &fragment, limits.proof)
                .map_err(WarpError::Finality)?;
            self.authorities = authorities;
            self.last_slot = fragment.header.slot;
            self.last_final = Some(target);
            self.fragments = self
                .fragments
                .checked_add(1)
                .ok_or(WarpError::ResourceLimit)?;
        }
        Ok(())
    }

    fn receive_headers(
        &mut self,
        params: &Params,
        blocks: Vec<smoldot::jam::types::Block>,
        header_bytes: usize,
    ) -> Result<(), WarpError> {
        let advertised = self.final_head.as_ref().ok_or(WarpError::InvalidJoin)?;
        if blocks.len() != 1 || self.head.is_some() {
            return Err(WarpError::InvalidJoin);
        }
        let f = blocks
            .into_iter()
            .next()
            .ok_or(WarpError::InvalidJoin)?
            .header;
        if f.hash(params) != advertised.hash
            || f.slot != advertised.slot
            || f.slot < self.last_slot
            || f.encode(params).len() > header_bytes
        {
            return Err(WarpError::InvalidJoin);
        }
        // The fragment's proof used the outgoing set. Its successful advancement
        // already authenticated this exact header, signed its posterior root and
        // consumed its rotation.
        self.finalized = self
            .last_final
            .filter(|last| last.hash == advertised.hash && last.slot == f.slot);
        self.head = Some(f);
        Ok(())
    }

    fn authenticate(
        &mut self,
        params: &Params,
        bytes: &[u8],
        limits: finality::Limits,
    ) -> Result<(), WarpError> {
        if self.finalized.is_some() {
            return Err(WarpError::InvalidJoin);
        }
        let f = self.head.as_ref().ok_or(WarpError::InvalidJoin)?;
        let hash = f.hash(params);
        let proof = Justification::decode(params, bytes, limits).map_err(WarpError::Finality)?;
        let verified = proof
            .verify(
                params,
                self.authorities.set_id(),
                self.authorities.current(),
                &hash,
                limits,
                |h| (*h == hash).then_some((hash, f.parent, f.prior_state_root, f.slot)),
            )
            .map_err(WarpError::Finality)?;
        if let Some(authorities) = self
            .authorities
            .after_finalizing(
                params,
                &verified,
                hash,
                f.slot,
                f.epoch_mark.as_ref().map(|mark| mark.validators.as_slice()),
            )
            .map_err(WarpError::Finality)?
        {
            self.authorities = authorities;
        }
        self.finalized = Some(*verified.target());
        Ok(())
    }

    /// Reads at F itself against the posterior root its justification signs.
    fn next_read(&self) -> Result<StateRead, WarpError> {
        let target = self.finalized.as_ref().ok_or(WarpError::InvalidJoin)?;
        let index = *[4, 6, 8, 11]
            .get(self.items.len())
            .ok_or(WarpError::InvalidJoin)?;
        let key = trie::state_key(index);
        Ok(StateRead {
            at: target.hash,
            root: target.state_root,
            trust: Trust::Finalized,
            root_header: Some(target.hash),
            // The captured full range costs more bytes but saves three round trips.
            // An honest early stop falls back to the remaining individual keys.
            request: StateRequest {
                block: target.hash,
                start: key,
                end: if self.items.is_empty() {
                    trie::state_key(11)
                } else {
                    key
                },
                max_size: 800_000,
            },
        })
    }
}

/// Trust of the caller-authenticated header carrying this posterior state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trust {
    Finalized,
    Authenticated,
}

#[derive(Clone, Debug)]
pub(crate) struct StateRead {
    pub at: Hash,
    pub root: Hash,
    pub trust: Trust,
    /// Header whose posterior root `root` is: the read block itself when a
    /// GRANDPA target signs it (the warp join), or its child when the root is
    /// that child's prior state root (`State::finalized_read`).
    pub root_header: Option<Hash>,
    pub request: StateRequest,
}

#[derive(Debug)]
pub(crate) struct StateReadResult {
    pub at: Hash,
    pub root: Hash,
    pub trust: Trust,
    pub root_header: Option<Hash>,
    pub range: VerifiedRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateReadError {
    Unavailable,
}

struct StateReads {
    pending: Option<(
        StateRead,
        futures_channel::oneshot::Sender<Result<StateReadResult, StateReadError>>,
    )>,
    owner: Option<usize>,
    attempts: u8,
    peers: usize,
}

#[cfg(test)]
impl Default for StateReads {
    fn default() -> Self {
        Self::new(MAX_PEERS)
    }
}

impl StateReads {
    fn new(peers: usize) -> Self {
        Self {
            pending: None,
            owner: None,
            attempts: 0,
            peers: peers.min(MAX_PEERS),
        }
    }

    fn finish_exhausted(&mut self) {
        if self.owner.is_none()
            && (0..self.peers).all(|peer| self.attempts & (1u8 << peer) != 0)
            && let Some((_, tx)) = self.pending.take()
        {
            let _ = tx.send(Err(StateReadError::Unavailable));
        }
    }
    /// Bounded in-process API: caller supplies the authenticated root and trust.
    /// Dropping the receiver cancels the read at the next reservation/response.
    fn start(
        &mut self,
        read: StateRead,
    ) -> Result<
        futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>,
        net::Error,
    > {
        if read.at != read.request.block
            || read.request.start > read.request.end
            || read.request.max_size == 0
        {
            return Err(net::Error::InvalidRequest);
        }
        if self.owner.is_none()
            && self
                .pending
                .as_ref()
                .is_some_and(|(_, tx)| tx.is_canceled())
        {
            self.pending = None;
        }
        if self.pending.is_some() || self.owner.is_some() {
            return Err(net::Error::Limit);
        }
        let (tx, rx) = futures_channel::oneshot::channel();
        self.pending = Some((read, tx));
        self.attempts = 0;
        self.finish_exhausted();
        Ok(rx)
    }

    fn reserve(&mut self, peer: usize) -> Option<StateRequest> {
        if peer >= self.peers || self.owner.is_some() {
            return None;
        }
        let (read, tx) = self.pending.as_ref()?;
        if tx.is_canceled() {
            self.pending = None;
            return None;
        }
        let bit = 1u8 << peer;
        if self.attempts & bit != 0 {
            return None;
        }
        self.attempts |= bit;
        self.owner = Some(peer);
        Some(read.request.clone())
    }

    fn release(&mut self, peer: usize, transient: bool) {
        if self.owner == Some(peer) {
            self.owner = None;
            if transient && peer < MAX_PEERS {
                self.attempts &= !(1u8 << peer);
            }
            self.finish_exhausted();
        }
    }

    fn received(&mut self, peer: usize, response: &StateResponse) -> Result<(), trie::ProofError> {
        if self.owner != Some(peer) {
            return Err(trie::ProofError::InvalidRange);
        }
        self.owner = None;
        let (read, _) = self
            .pending
            .as_ref()
            .ok_or(trie::ProofError::InvalidRange)?;
        let range = match trie::verify_range(&read.root, &read.request, response) {
            Ok(range) => range,
            Err(error) => {
                self.finish_exhausted();
                return Err(error);
            }
        };
        if let Some((read, tx)) = self.pending.take() {
            let _ = tx.send(Ok(StateReadResult {
                at: read.at,
                root: read.root,
                trust: read.trust,
                root_header: read.root_header,
                range,
            }));
        }
        Ok(())
    }
}

#[derive(Debug)]
enum InsertFailure {
    ResourceLimit,
    Tree(tree::InsertError),
}

impl State {
    /// Wait until the best chain has an authenticated child of the finalized head.
    fn finalized_read(
        &self,
        start: trie::StateKey,
        end: trie::StateKey,
        max_size: u32,
    ) -> Option<StateRead> {
        let at = self.tree.finalized().hash;
        let child = self
            .tree
            .ancestors(&self.tree.best().hash)
            .find(|child| child.parent == at)?;
        let root = child.encoded.get(32..64)?.try_into().ok()?;
        Some(StateRead {
            at,
            root,
            trust: Trust::Authenticated,
            root_header: Some(child.hash),
            request: StateRequest {
                block: at,
                start,
                end,
                max_size,
            },
        })
    }

    /// One bounded step of the `C(8)` refresh: collect a finished read, give up
    /// on one no peer is serving, or start one when it is due and the shared
    /// read slot is free. Never blocks; header sync is unaffected either way.
    fn discovery_turn(&mut self, now_unix: Duration) -> Option<DiscoveryEvent> {
        if let Some(read) = &mut self.discovery.read {
            let outcome = match read.rx.try_recv() {
                Ok(None) => {
                    // A reservation that ended without a result (a peer said
                    // NoData, faulted, or its connection closed) is not retried
                    // here: the slot stays free for warp joins and proofs, and
                    // the next finality advance tries again.
                    if self.reads.owner.is_some() || self.reads.attempts == 0 {
                        return None;
                    }
                    Err("Released")
                }
                Ok(Some(Ok(result))) => Ok(result),
                Ok(Some(Err(StateReadError::Unavailable))) => Err("Unavailable"),
                Err(_) => Err("Cancelled"),
            };
            let read = self.discovery.read.take()?;
            return Some(match outcome {
                Ok(result) => self.apply_active_set(&read, result, now_unix),
                Err(reason) => DiscoveryEvent::Failed { reason },
            });
        }
        if !self.discovery.due || self.stopped || self.warp_owner.is_some() {
            return None;
        }
        let key = trie::state_key(8);
        // `None` until the best chain has an authenticated child; stay due.
        let expected = self.finalized_read(key, key, ACTIVE_SET_READ_BYTES)?;
        let rx = self.reads.start(expected.clone()).ok()?;
        self.discovery.due = false;
        self.discovery.read = Some(DiscoveryRead {
            expected,
            rx,
            started_ms: now_unix.as_millis(),
        });
        Some(DiscoveryEvent::Started {
            slot: self.tree.finalized().slot,
        })
    }

    fn apply_active_set(
        &mut self,
        read: &DiscoveryRead,
        result: StateReadResult,
        now_unix: Duration,
    ) -> DiscoveryEvent {
        let expected = &read.expected;
        if result.at != expected.at
            || result.root != expected.root
            || result.trust != Trust::Authenticated
            || result.root_header != expected.root_header
        {
            return DiscoveryEvent::Failed {
                reason: "Provenance",
            };
        }
        let key = trie::state_key(8);
        let Some((_, value)) = result.range.entries.iter().find(|(k, _)| *k == key) else {
            return DiscoveryEvent::Failed { reason: "Absent" };
        };
        let Ok(validators) = metadata::decode_active_set(&self.params, value) else {
            return DiscoveryEvent::Failed { reason: "Decode" };
        };
        let merge = self.discovery.pool.replace_discovered(
            validators.len(),
            validators
                .iter()
                .map(|key| Peer::discovered(&ValidatorEndpoint::from_validator(key))),
        );
        self.discovery.stale = false;
        DiscoveryEvent::Refreshed {
            merge,
            value_bytes: value.len(),
            elapsed_ms: now_unix.as_millis().saturating_sub(read.started_ms),
        }
    }

    /// Slots in `cleared` no longer hold the peer their per-slot state
    /// describes: forget their refusal, proof attempts and read attempt, so the
    /// terminal stop keeps meaning "the peers held right now refused this root".
    fn slots_changed(&mut self, cleared: u8) {
        if cleared == 0 {
            return;
        }
        if let Some((_, mask)) = &mut self.root_refusals {
            *mask &= !cleared;
        }
        for (_, attempts) in &mut self.proof_attempts {
            *attempts &= !cleared;
        }
        let owner = self.reads.owner.map_or(0, |owner| 1u8 << owner);
        self.reads.attempts &= !(cleared & !owner);
    }

    /// Assigns `slot` a candidate, or says how long to wait (`None`: until the
    /// pool changes). Clears the per-slot state of every slot whose peer changed.
    fn acquire_candidate(&mut self, slot: usize, now: Duration) -> Result<Peer, Option<Duration>> {
        match self.discovery.pool.acquire(slot, now) {
            Acquire::Peer { peer, cleared } => {
                self.slots_changed(cleared);
                Ok(peer)
            }
            Acquire::Wait(wait) => Err(wait),
        }
    }

    /// Switch `slot` to a due bootnode, only while it owns no shared work.
    fn preempt_candidate(&mut self, slot: usize, now: Duration) -> Option<Peer> {
        if self.stopped
            || self.warp_owner == Some(slot)
            || self.reads.owner == Some(slot)
            || self.proof_owner.is_some_and(|(owner, _)| owner == slot)
        {
            return None;
        }
        let (peer, cleared) = self.discovery.pool.preempt(slot, now)?;
        self.slots_changed(cleared);
        Some(peer)
    }

    fn reserve_warp(&mut self, peer: usize) -> Option<Warp> {
        // Discovery yields to a warp join: a refresh that no peer is serving
        // right now is cancelled, and retried at the next finality advance.
        if self.reads.owner.is_none() && self.discovery.read.take().is_some() {
            self.discovery.due = false;
        }
        if self.reads.owner.is_none()
            && self
                .reads
                .pending
                .as_ref()
                .is_some_and(|(_, tx)| tx.is_canceled())
        {
            self.reads.pending = None;
        }
        if self.stopped
            || self.warp_owner.is_some()
            || self.proof_owner.is_some()
            || self.reads.owner.is_some()
            || self.reads.pending.is_some()
        {
            return None;
        }
        self.warp_owner = Some(peer);
        Some(Warp::new(self))
    }

    fn apply_warp(&mut self, peer: usize, warp: Warp) -> Result<(), WarpError> {
        if self.stopped
            || self.warp_owner != Some(peer)
            || self.tree.finalized().hash != warp.anchor
        {
            return Err(WarpError::StaleAnchor);
        }
        let (Some(target), Some(head)) = (warp.finalized, warp.head) else {
            return Err(WarpError::InvalidJoin);
        };
        if warp.items.len() != 4 || head.hash(&self.params) != target.hash {
            return Err(WarpError::InvalidJoin);
        }
        // The items were proven against F's signed posterior root, so they are
        // the state after F: anchor at F directly, as a checkpoint would.
        let raw = GenesisLightState::from_state_items(
            &self.params,
            warp.items.iter().map(|(k, v)| (k, v.as_slice())),
        )
        .map_err(|_| WarpError::InvalidJoin)?;
        if raw.slot != head.slot {
            return Err(WarpError::InvalidJoin);
        }
        let state = LightState::from_anchor(&self.params, &raw).map_err(WarpError::State)?;
        let root = verified_genesis(&self.params, head, state);
        let tree = HeaderTree::new(self.params.clone(), root, self.tree_config)
            .map_err(WarpError::Tree)?;
        let revision = self
            .warp_revision
            .checked_add(1)
            .ok_or(WarpError::ResourceLimit)?;
        self.tree = tree;
        self.authorities = warp.authorities;
        self.warp_revision = revision;
        self.warp_owner = None;
        self.proof_attempts.clear();
        self.root_refusals = None;
        self.subscribers.clear();
        // A new anchor may sit in a later epoch; read again after its first
        // finality advance.
        self.discovery.stale = true;
        self.discovery.due = false;
        Ok(())
    }

    fn refuse_root(&mut self, peer: usize, hash: Hash) -> Result<(), AnchorUnserved> {
        if hash != self.tree.finalized().hash || peer >= MAX_PEERS {
            return Ok(());
        }
        let old = self
            .root_refusals
            .filter(|(root, _)| *root == hash)
            .map_or(0, |(_, mask)| mask);
        let mask = old | (1u8 << peer);
        self.root_refusals = Some((hash, mask));
        self.stop_if_unserved()
    }

    fn stop_if_unserved(&mut self) -> Result<(), AnchorUnserved> {
        let mask = self
            .root_refusals
            .filter(|(hash, _)| *hash == self.tree.finalized().hash)
            .map_or(0, |(_, mask)| mask);
        // A concurrently staged warp may still replace the refused anchor.
        if self.warp_owner.is_none()
            && self.peer_count == MAX_PEERS
            && mask.count_ones() >= u32::try_from(self.peer_count).unwrap_or(u32::MAX)
        {
            self.stopped = true;
            self.subscribers.clear();
            return Err(AnchorUnserved {
                hash: self.tree.finalized().hash,
                slot: self.tree.finalized().slot,
            });
        }
        Ok(())
    }

    fn proof_limits(&self) -> finality::Limits {
        let witnesses = (FRAME_BYTES / self.header_bytes).max(1);
        finality::Limits {
            max_bytes: FRAME_BYTES,
            max_ancestry_headers: witnesses,
            max_ancestry_steps: self
                .tree
                .len()
                .saturating_add(witnesses)
                .saturating_mul(usize::from(self.params.max_validators))
                .saturating_mul(2),
        }
    }

    /// Select an authenticated target, stopping at the first unfinalized epoch
    /// mark. Advertisements trigger fetching but never supply authority state.
    fn reserve_proof(&mut self, peer: usize, advertised: &Final) -> Option<Hash> {
        if self.stopped
            || self.warp_owner.is_some()
            || self.proof_owner.is_some()
            || advertised.slot <= self.tree.finalized().slot
        {
            return None;
        }
        let tip = self
            .tree
            .get(&advertised.hash)
            .unwrap_or_else(|| self.tree.best());
        let path: Vec<_> = self
            .tree
            .ancestors(&tip.hash)
            .take_while(|b| b.hash != self.tree.finalized().hash)
            .collect();
        let candidate = path
            .iter()
            .rev()
            .find(|b| b.epoch_changed)
            .copied()
            .or_else(|| path.first().copied())?;
        if candidate.slot > advertised.slot {
            return None;
        }
        let target = candidate.hash;
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash
        });
        let bit = 1u8 << peer;
        if let Some((_, attempts)) = self
            .proof_attempts
            .iter_mut()
            .find(|(hash, _)| *hash == target)
        {
            if *attempts & bit != 0 {
                return None;
            }
            *attempts |= bit;
        } else {
            self.proof_attempts.push((target, bit));
        }
        self.proof_owner = Some((peer, target));
        Some(target)
    }

    fn finalize(&mut self, target: Hash, bytes: &[u8]) -> Result<(), finality::Error> {
        let before = self.tree.finalized().slot;
        let limits = self.proof_limits();
        let proof = Justification::decode(&self.params, bytes, limits)?;
        let verified = proof.verify(
            &self.params,
            self.authorities.set_id(),
            self.authorities.current(),
            &target,
            limits,
            |hash| self.tree.get(hash).and_then(finality::ancestry_link),
        )?;
        let result = self.tree.finalize(&verified, &mut self.authorities)?;
        if result.finalized.is_empty() {
            return Ok(());
        }
        // The active set changes only with an epoch mark, and every epoch's
        // first block carries one; comparing epochs also covers skipped ones.
        let after = self.tree.finalized().slot;
        let epoch_len = self.params.epoch_len.max(1);
        if before / epoch_len != after / epoch_len {
            self.discovery.stale = true;
        }
        if self.discovery.stale {
            self.discovery.due = true;
        }
        let notification = Notification::Finalized {
            finalized_blocks_hashes: result.finalized,
            pruned_blocks: result.pruned,
            best_block_hash_if_changed: result.best_changed.then(|| self.tree.best().hash),
        };
        self.subscribers
            .retain(|tx| tx.try_send(notification.clone()).is_ok());
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash
        });
        Ok(())
    }

    fn subscribe(&mut self, buffer_size: usize, runtime_interest: bool) -> SubscribeAll {
        self.subscribers.retain(|s| !s.is_closed());
        let queue_limit = (1024 * 1024 / self.header_bytes).clamp(1, 16);
        let (tx, rx) = async_channel::bounded(buffer_size.clamp(1, queue_limit));
        if !runtime_interest && !self.stopped && self.subscribers.len() < MAX_SUBSCRIBERS {
            self.subscribers.push(tx);
        }
        SubscribeAll {
            finalized_block_scale_encoded_header: self.tree.finalized().encoded.clone(),
            finalized_block_runtime: None,
            non_finalized_blocks_ancestry_order: self
                .tree
                .ancestry_order()
                .skip(1)
                .map(|b| BlockNotification {
                    is_new_best: b.hash == self.tree.best().hash,
                    scale_encoded_header: b.encoded.clone(),
                    parent_hash: b.parent,
                })
                .collect(),
            new_blocks: rx,
        }
    }

    fn insert(&mut self, header: Header, now: u64) -> Result<(), InsertFailure> {
        if self.stopped || header.encode(&self.params).len() > self.header_bytes {
            return Err(InsertFailure::ResourceLimit);
        }
        let hash = header.hash(&self.params);
        let extends_root = header.parent == self.tree.finalized().hash;
        #[cfg(test)]
        let preverified = self.test_verifier.map(|verify| {
            let parent = self
                .tree
                .get(&header.parent)
                .ok_or(tree::InsertError::UnknownParent)?;
            self.tree
                .insert_verified(header.parent, verify(&self.params, parent, header.clone()))
        });
        #[cfg(test)]
        let result = preverified.unwrap_or_else(|| self.tree.insert(header.parent, header, now));
        #[cfg(not(test))]
        let result = self.tree.insert(header.parent, header, now);
        match result {
            Ok(tree::Insert::AlreadyKnown) => {
                if extends_root {
                    self.root_refusals = None;
                }
                Ok(())
            }
            Ok(tree::Insert::Inserted { evicted, .. }) => {
                if extends_root {
                    self.root_refusals = None;
                }
                if !evicted.is_empty() {
                    self.subscribers.clear();
                }
                if let Some(block) = self.tree.get(&hash) {
                    let notification = Notification::Block(BlockNotification {
                        is_new_best: self.tree.best().hash == hash,
                        scale_encoded_header: block.encoded.clone(),
                        parent_hash: block.parent,
                    });
                    self.subscribers
                        .retain(|tx| tx.try_send(notification.clone()).is_ok());
                }
                Ok(())
            }
            Err(tree::InsertError::Full) => {
                self.stopped = true;
                self.subscribers.clear();
                Err(InsertFailure::Tree(tree::InsertError::Full))
            }
            Err(error) => Err(InsertFailure::Tree(error)),
        }
    }
}

pub(super) async fn run<P: PlatformRef>(
    platform: P,
    log_name: String,
    config: Config,
    rx: async_channel::Receiver<ToBackground>,
) {
    // Slots keep their index for life; only their candidate changes. Without
    // any dialable bootnode or genesis validator there is nobody to dial.
    let slots = if config.peers.is_empty() && config.genesis.is_empty() {
        0
    } else {
        MAX_PEERS
    };
    let pool = Pool::new(
        config.peers,
        config.genesis,
        usize::from(config.params.max_validators),
    );
    // Bounded by 16 bootnodes plus `max_validators`, once per start.
    let count = |source| pool.candidates().filter(|p| p.source == source).count();
    log!(
        &platform,
        Debug,
        &log_name,
        "jam-pool-initial",
        bootnodes = count(Source::Bootnode),
        genesis = count(Source::Genesis),
        max_discovered = config.params.max_validators,
        slots = slots
    );
    for (index, peer) in pool.candidates().enumerate() {
        log!(
            &platform,
            Debug,
            &log_name,
            "jam-pool-candidate",
            index = index,
            source = peer.source.as_str(),
            address = peer.address(),
            p256 = peer.identity.to_text()
        );
    }
    let state = Arc::new(async_lock::Mutex::new(State {
        reads: StateReads::new(slots),
        #[cfg(test)]
        test_verifier: None,
        tree: config.tree,
        params: config.params.clone(),
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
        peer_count: slots,
        discovery: Discovery::new(pool),
    }));
    let foreground = async {
        while let Ok(request) = rx.recv().await {
            match request {
                ToBackground::SubscribeAll {
                    send_back,
                    buffer_size,
                    runtime_interest,
                } => {
                    let _ =
                        send_back.send(state.lock().await.subscribe(buffer_size, runtime_interest));
                }
                ToBackground::SerializeChainInformation { send_back } => {
                    let _ = send_back.send(None);
                }
                ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                    let _ = send_back.send(false);
                }
                ToBackground::SyncingPeers { send_back } => {
                    let _ = send_back.send(Vec::new());
                }
                ToBackground::PeersAssumedKnowBlock { send_back, .. } => {
                    let _ = send_back.send(Vec::new());
                }
                ToBackground::SubscribeSyncStatus { send_back } => {
                    let (tx, rx) = async_channel::bounded(1);
                    let _ = tx.try_send(SyncStatus::Ready);
                    let _ = send_back.send(rx);
                }
            }
        }
    };
    // Peer drivers must yield to the platform executor, not to a FuturesUnordered
    // that can immediately repoll the same child within one outer task poll.
    let (shutdown, cancelled) = async_channel::bounded::<()>(1);
    let mut peers_done = futures_util::stream::FuturesUnordered::new();
    let origin = platform.now();
    for slot in 0..slots {
        // Assign in slot order so the first bootnodes go to the first slots.
        let initial = state
            .lock()
            .await
            .acquire_candidate(slot, Duration::ZERO)
            .ok();
        let (done, finished) = futures_channel::oneshot::channel();
        peers_done.push(finished);
        let platform_ref = platform.clone();
        let log_name = log_name.clone();
        let params = config.params.clone();
        let state = state.clone();
        let cancelled = cancelled.clone();
        let origin = origin.clone();
        platform.spawn_task(alloc::format!("jam-peer-{log_name}").into(), async move {
            future::or(
                slot_loop(
                    &platform_ref,
                    &log_name,
                    slot,
                    &params,
                    state,
                    origin,
                    initial,
                ),
                async {
                    let _ = cancelled.recv().await;
                },
            )
            .await;
            let _ = done.send(());
        });
    }
    foreground.await;
    // Closing the sole sender cancels all drivers, including pending connect,
    // stream-opening, readiness and backoff waits. Await transport cleanup.
    drop(shutdown);
    while peers_done.next().await.is_some() {}
}

/// One connection slot. It keeps `slot` as its `peer_index` for life and asks
/// the pool for a candidate whenever it has none: on a failed connect or an
/// ended connection it releases the candidate (recording the failure against
/// that candidate) and asks again, so backoff is per candidate, not per slot.
async fn slot_loop<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    slot: usize,
    params: &Params,
    state: Arc<async_lock::Mutex<State>>,
    origin: P::Instant,
    mut current: Option<Peer>,
) {
    let mut fetch_size = FetchSize::default();
    let mut root_probe = None;
    let mut previous: Option<smoldot::jam::types::Ed25519Public> = None;
    // Log a wait once when it starts, not once per poll.
    let mut waiting = false;
    loop {
        if state.lock().await.stopped {
            future::pending::<()>().await;
        }
        let peer = match current.take() {
            Some(peer) => peer,
            None => {
                let now = platform.now() - origin.clone();
                // Bind first: a guard in the scrutinee would be held while sleeping.
                let acquired = state.lock().await.acquire_candidate(slot, now);
                match acquired {
                    Ok(peer) => peer,
                    Err(wait) => {
                        if !waiting {
                            waiting = true;
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-pool-waiting",
                                slot = slot,
                                ready_in_ms = Opt(wait.map(|wait| wait.as_millis()))
                            );
                        }
                        let wait = wait.map_or(POOL_POLL, |wait| wait.min(POOL_POLL));
                        platform.sleep(wait.max(Duration::from_millis(1))).await;
                        continue;
                    }
                }
            }
        };
        waiting = false;
        log!(
            platform,
            Debug,
            log_name,
            "jam-slot-assigned",
            slot = slot,
            source = peer.source.as_str(),
            address = peer.address(),
            p256 = peer.identity.to_text()
        );
        if previous != Some(peer.ed25519) {
            // The root probe describes one peer's answers, not the slot's.
            root_probe = None;
            previous = Some(peer.ed25519);
        }
        let outcome = connect_once(
            platform,
            log_name,
            &peer,
            slot,
            params,
            &state,
            (&mut fetch_size, &mut root_probe),
            Some(origin.clone()),
        )
        .await;
        let now = platform.now() - origin.clone();
        match outcome {
            None => {
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-slot-unsupported",
                    slot = slot,
                    address = peer.address()
                );
                state
                    .lock()
                    .await
                    .discovery
                    .pool
                    .release(slot, Release::Unsupported, now);
                continue;
            }
            Some(Outcome { stopped: true, .. }) => continue,
            Some(Outcome {
                preempted: Some(next),
                ..
            }) => {
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-slot-preempted",
                    slot = slot,
                    from = peer.address(),
                    to = next.address()
                );
                current = Some(next);
            }
            Some(Outcome { lasted, .. }) => {
                state
                    .lock()
                    .await
                    .discovery
                    .pool
                    .release(slot, Release::Ended { lasted }, now);
            }
        }
        log!(platform, Debug, log_name, "jam-reconnect");
    }
}

/// How one connection attempt ended.
struct Outcome {
    /// Zero when the transport never connected.
    lasted: Duration,
    /// The driver stopped the chain; the slot parks.
    stopped: bool,
    /// The pool moved this slot to this bootnode while connected.
    preempted: Option<Peer>,
}

/// Dial `peer` once on slot `peer_index` and drive the connection until it
/// ends, then release the proof, warp and read ownership it may hold.
/// `None` when the platform cannot dial this address type. With `preempt`
/// (the pool's time origin), a slot on a discovered peer may be moved to a
/// bootnode whose retry interval has passed.
#[allow(clippy::too_many_arguments)]
async fn connect_once<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    peer: &Peer,
    peer_index: usize,
    params: &Params,
    state: &Arc<async_lock::Mutex<State>>,
    (fetch_size, root_probe): (&mut FetchSize, &mut Option<Hash>),
    preempt: Option<P::Instant>,
) -> Option<Outcome> {
    let address = MultiStreamAddress::WebTransport {
        ip: peer.ip,
        port: peer.port,
        cert_hashes: Cow::Owned(
            jam_webtransport_cert::certificate_hashes(
                &peer.identity,
                platform.now_from_unix_epoch().as_secs(),
            )
            .to_vec(),
        ),
    };
    if !platform.supports_connection_type((&address).into()) {
        return None;
    }
    log!(platform, Debug, log_name, "jam-connect");
    let connected = future::or(
        async { Some(platform.connect_multistream(address).await) },
        async {
            platform.sleep(TIMEOUT).await;
            None
        },
    )
    .await;
    let mut outcome = Outcome {
        lasted: Duration::ZERO,
        stopped: false,
        preempted: None,
    };
    let Some(connected) = connected else {
        log!(
            platform,
            Debug,
            log_name,
            "jam-peer-disconnected",
            slot = peer_index,
            source = peer.source.as_str(),
            address = peer.address(),
            lasted_ms = 0,
            reason = End::ConnectTimeout.as_str()
        );
        return Some(outcome);
    };
    let started = platform.now();
    let driving = async {
        Err(drive_connection(
            platform,
            log_name,
            params,
            peer_index,
            state,
            connected.connection,
            (fetch_size, root_probe),
        )
        .await)
    };
    let ended: Result<Peer, End> = match preempt {
        Some(origin) if peer.source != Source::Bootnode => {
            future::or(driving, async {
                loop {
                    platform.sleep(PREEMPT_POLL).await;
                    let now = platform.now() - origin.clone();
                    if let Some(next) = state.lock().await.preempt_candidate(peer_index, now) {
                        return Ok(next);
                    }
                }
            })
            .await
        }
        _ => driving.await,
    };
    let reason = match &ended {
        Ok(_) => End::Preempted,
        Err(end) => *end,
    };
    outcome.preempted = ended.ok();
    outcome.lasted = platform.now() - started;
    let mut s = state.lock().await;
    s.reads.release(peer_index, false);
    if s.proof_owner.is_some_and(|(owner, _)| owner == peer_index) {
        s.proof_owner = None;
    }
    if s.warp_owner == Some(peer_index) {
        s.warp_owner = None;
    }
    outcome.stopped = s.stopped;
    drop(s);
    log!(
        platform,
        Debug,
        log_name,
        "jam-peer-disconnected",
        slot = peer_index,
        source = peer.source.as_str(),
        address = peer.address(),
        lasted_ms = outcome.lasted.as_millis(),
        reason = reason.as_str()
    );
    Some(outcome)
}

/// A connection loop pinned to one peer, with the slot-wide backoff the
/// driver had before the pool. Scripted tests use it to drive a fixed peer
/// on a chosen slot.
#[cfg(test)]
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

struct Stream<P: PlatformRef> {
    id: u64,
    stream: Pin<Box<P::Stream>>,
    opened: P::Instant,
    limited_lifetime: bool,
    request: Option<net::RequestId>,
}

/// Retained across reconnects so an oversized response cannot repeat forever.
struct FetchSize {
    count: u32,
    ceiling: u32,
}
impl Default for FetchSize {
    fn default() -> Self {
        Self {
            count: 1,
            ceiling: 64,
        }
    }
}
impl FetchSize {
    fn received(&mut self, bytes: usize) {
        if bytes < FRAME_BYTES / 2 {
            self.count = (self.count * 2).min(self.ceiling);
        }
    }
    fn oversized(&mut self) {
        self.count = (self.count / 2).max(1);
        self.ceiling = self.count;
    }
}

/// F5's classifier, unchanged from the saved D7 change. Kept here so D2 can
/// stand alone below D7 without interpreting numbers in browser prose.
fn classify_reset(message: &str) -> net::RequestError {
    match message
        .strip_prefix("jamnp-stream-reset:")
        .and_then(|message| message.split_once(' '))
        .map(|(code, _)| code)
    {
        Some("6") => net::RequestError::NoData,
        Some("2" | "3" | "4" | "5") => net::RequestError::Transient,
        _ => net::RequestError::Rejected,
    }
}

/// [`drive_connection`] for tests, which drive one connection without its end reason.
#[cfg(test)]
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

/// Where a warp join stands, for `jam-warp-abandoned`.
fn warp_step(warp: &Warp) -> &'static str {
    if !warp.chain_done {
        "fragments"
    } else if warp.head.is_none() {
        "head"
    } else if warp.finalized.is_none() {
        "justification"
    } else {
        "state"
    }
}

/// Drives one connection until it ends and says why.
async fn drive_connection<P: PlatformRef>(
    platform: &P,
    log_name: &str,
    params: &Params,
    peer_index: usize,
    state: &Arc<async_lock::Mutex<State>>,
    mut transport: P::MultiStream,
    (fetch_size, root_probe): (&mut FetchSize, &mut Option<Hash>),
) -> End {
    let handshake = {
        let s = state.lock().await;
        Handshake {
            final_: Final {
                hash: s.tree.finalized().hash,
                slot: s.tree.finalized().slot,
            },
            leaves: s.tree.leaves().into_iter().take(8).collect(),
        }
    };
    if root_probe.is_some_and(|hash| hash != handshake.final_.hash) {
        *root_probe = None;
    }
    let Ok(mut connection) = net::Connection::new(
        params.clone(),
        handshake,
        net::Limits {
            max_message_size: FRAME_BYTES,
            max_warp_message_size: WARP_BYTES,
            max_body_bytes: FRAME_BYTES,
            max_leaves_in_handshake: 8,
            max_pending_requests: 2,
            max_streams: 4,
        },
    ) else {
        return End::Setup;
    };
    let mut streams: Vec<Stream<P>> = Vec::new();
    let mut opening: Option<(net::SubstreamKind, P::Instant)> = None;
    let mut next_id = 0u64;
    let mut handshaken = false;
    let started = platform.now();
    let mut last_activity = started.clone();
    let mut peer_slot = 0;
    // A fallback cursor can traverse known headers without changing local best.
    let mut cursor = None;
    // The root probe is retained by peer_loop across transient failures. The
    // remaining cursors and repair buffers belong to this connection only.
    let mut fallback = false;
    let mut waiting_for_finality = None;
    let mut repair = Vec::new();
    let mut imports = VecDeque::new();
    let mut repair_ready = false;
    let mut announcements = VecDeque::new();
    let mut requested: Option<(net::RequestId, BlockRequest, P::Instant, Tag)> = None;
    let mut proof_requested: Option<(net::RequestId, Hash, P::Instant, Tag)> = None;
    let mut state_requested: Option<(net::RequestId, P::Instant, Tag)> = None;
    let mut advertised: Option<Final> = None;
    let mut advertisement_revision = 0u64;
    let mut warped = false;
    let mut warp: Option<Warp> = None;
    let mut warp_requested: Option<(net::RequestId, u32, P::Instant, Tag)> = None;
    let mut warp_revision = state.lock().await.warp_revision;
    let elapsed_ms = |when: &P::Instant| (platform.now() - when.clone()).as_millis();
    let end = 'conn: loop {
        // A turn performs bounded protocol work and at most one ancestry insertion.
        // In particular, never retain the shared tree lock across this yield: RPC
        // consumers and the other peer must be able to run between notifications.
        future::yield_now().await;
        {
            let s = state.lock().await;
            if s.stopped {
                break 'conn End::Stopped;
            }
            if s.warp_revision != warp_revision {
                break 'conn End::WarpRevision;
            }
        }
        let mut local_progress = false;
        let now = platform.now();
        if !handshaken && now.clone() - started.clone() >= TIMEOUT {
            break 'conn End::HandshakeTimeout;
        }
        if now.clone() - last_activity.clone() >= IDLE_TIMEOUT {
            break 'conn End::Idle;
        }
        if let Some((kind, when)) = &opening
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.outgoing_open_failed(*kind);
            break 'conn End::StreamOpenTimeout;
        }
        // This deadline starts while the request is still queued, before a stream
        // reservation exists. Peer-created streams cannot starve it indefinitely.
        if let Some((id, when, _)) = &state_requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            state.lock().await.reads.release(peer_index, false);
            break 'conn End::StateTimeout;
        }
        if let Some((id, _, when, _)) = &requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            break 'conn End::BlockTimeout;
        }
        if let Some((id, _, when, _)) = &proof_requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            break 'conn End::JustificationTimeout;
        }
        if let Some((id, _, when, _)) = &warp_requested
            && now.clone() - when.clone() >= TIMEOUT
        {
            let _ = connection.cancel_request(*id, net::RequestError::Timeout);
            break 'conn End::WarpTimeout;
        }
        if streams
            .iter()
            .any(|s| s.limited_lifetime && now.clone() - s.opened.clone() >= TIMEOUT)
        {
            break 'conn End::StreamTimeout;
        }
        if opening.is_none()
            && let Some(kind) = connection.desired_outgoing_substreams()
        {
            opening = Some((kind, now.clone()));
            platform.open_out_substream(&mut transport);
        }
        let mut events = Vec::new();
        let mut proof_unavailable = false;
        let mut index = 0;
        while index < streams.len() {
            let stream = &mut streams[index];
            let request = stream.request;
            let (mut access, error) = match platform.read_write_access(stream.stream.as_mut()) {
                Ok(access) => (Some(access), None),
                Err(error) => (None, Some(alloc::format!("{error}"))),
            };
            if let Some(message) = error {
                let reason = classify_reset(&message);
                // Which of this connection's requests the stream carried.
                let owner = request.and_then(|id| {
                    state_requested
                        .as_ref()
                        .filter(|(r, ..)| *r == id)
                        .map(|(.., tag)| ("state", tag.req))
                        .or_else(|| {
                            requested
                                .as_ref()
                                .filter(|(r, ..)| *r == id)
                                .map(|(.., tag)| ("block", tag.req))
                        })
                        .or_else(|| {
                            proof_requested
                                .as_ref()
                                .filter(|(r, ..)| *r == id)
                                .map(|(.., tag)| ("justification", tag.req))
                        })
                        .or_else(|| {
                            warp_requested
                                .as_ref()
                                .filter(|(r, ..)| *r == id)
                                .map(|(.., tag)| ("warp", tag.req))
                        })
                });
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-stream-reset",
                    slot = peer_index,
                    stream = owner.map_or("other", |(kind, _)| kind),
                    req = Opt(owner.map(|(_, req)| req)),
                    reason = alloc::format!("{reason:?}"),
                    message = message
                );
                drop(access);
                if state_requested
                    .as_ref()
                    .is_some_and(|(id, ..)| request == Some(*id))
                {
                    if let Some(event) = connection.substream_reset(stream.id, reason) {
                        events.push(event);
                    }
                    streams.remove(index);
                    local_progress = true;
                    continue;
                }
                if let Some((id, _, when, tag)) = &proof_requested
                    && request == Some(*id)
                {
                    if warp.is_some() {
                        break 'conn End::StreamReset;
                    }
                    let _ = connection.cancel_request(*id, reason);
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-justification-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "failed",
                        error = alloc::format!("{reason:?}"),
                        elapsed_ms = elapsed_ms(when)
                    );
                    proof_requested = None;
                    proof_unavailable = true;
                    streams.remove(index);
                    local_progress = true;
                    continue;
                }
                if requested
                    .as_ref()
                    .is_some_and(|(id, ..)| request == Some(*id))
                    || warp_requested
                        .as_ref()
                        .is_some_and(|(id, ..)| request == Some(*id))
                {
                    if let Some(event) = connection.substream_reset(stream.id, reason) {
                        events.push(event);
                    }
                    streams.remove(index);
                    local_progress = true;
                    continue;
                }
                break 'conn End::StreamReset;
            }
            let mut rw = match access.take() {
                Some(rw) => rw,
                None => break 'conn End::Transport,
            };
            drop(access);
            let incoming_limit = if state_requested
                .as_ref()
                .is_some_and(|(id, ..)| request == Some(*id))
            {
                FRAME_BYTES + 496 * 64 + 8
            } else if warp_requested
                .as_ref()
                .is_some_and(|(id, ..)| request == Some(*id))
            {
                WARP_BYTES + 4
            } else {
                FRAME_BYTES + 4
            };
            if rw.incoming_buffer.len() > incoming_limit || rw.write_bytes_queued > 65536 {
                break 'conn End::Limit;
            }
            let mut output = [0; 4096];
            let queueable = rw
                .write_bytes_queueable
                .unwrap_or(0)
                .min(output.len())
                .min(65536usize.saturating_sub(rw.write_bytes_queued));
            let progress = connection.read_write(
                stream.id,
                &rw.incoming_buffer,
                rw.expected_incoming_bytes.is_none(),
                &mut output[..queueable],
            );
            local_progress |= progress.read != 0
                || progress.written != 0
                || progress.finish_write
                || progress.reset
                || progress.event.is_some();
            rw.incoming_buffer.drain(..progress.read);
            rw.read_bytes += progress.read;
            if let Some(expected) = &mut rw.expected_incoming_bytes {
                *expected = 1;
            }
            if progress.written != 0 {
                rw.write_from_vec(&mut output[..progress.written].to_vec());
            }
            if progress.finish_write {
                rw.close_write();
            }
            if progress.read != 0 {
                last_activity = now.clone();
            }
            let retired = progress.reset
                || matches!(
                    &progress.event,
                    Some(
                        net::Event::BlockResponse { .. }
                            | net::Event::StateResponse { .. }
                            | net::Event::JustificationResponse { .. }
                            | net::Event::WarpResponse { .. }
                            | net::Event::RequestFailed { .. }
                    )
                );
            drop(rw);
            if let Some(event) = progress.event {
                events.push(event);
            }
            if retired {
                streams.remove(index);
            } else {
                index += 1;
            }
        }
        if proof_unavailable {
            state.lock().await.proof_owner = None;
        }
        for event in events {
            match event {
                net::Event::StateResponse {
                    request_id,
                    response,
                } => {
                    let Some((id, when, tag)) = state_requested.take() else {
                        break 'conn End::UnexpectedResponse;
                    };
                    if id != request_id {
                        break 'conn End::UnexpectedResponse;
                    }
                    let entries = response.entries.len();
                    let nodes = response.nodes.len();
                    let bytes = state_response_bytes(&response);
                    if let Err(error) = state.lock().await.reads.received(peer_index, &response) {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-state-request-ended",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            outcome = "rejected",
                            entries = entries,
                            nodes = nodes,
                            bytes = bytes,
                            error = Token(&error),
                            elapsed_ms = elapsed_ms(&when)
                        );
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-state-rejected",
                            slot = peer_index,
                            req = tag.req,
                            error = alloc::format!("{error:?}")
                        );
                        break 'conn End::StateRejected;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-state-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "ok",
                        entries = entries,
                        nodes = nodes,
                        bytes = bytes,
                        elapsed_ms = elapsed_ms(&when)
                    );
                }
                net::Event::RequestFailed { request_id, reason }
                    if state_requested
                        .as_ref()
                        .is_some_and(|(id, ..)| *id == request_id) =>
                {
                    if let Some((_, when, tag)) = state_requested.take() {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-state-request-ended",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            outcome = "failed",
                            error = alloc::format!("{reason:?}"),
                            elapsed_ms = elapsed_ms(&when)
                        );
                    }
                    state
                        .lock()
                        .await
                        .reads
                        .release(peer_index, reason == net::RequestError::Transient);
                    if warp.is_some() || reason != net::RequestError::NoData {
                        break 'conn End::StateFailed;
                    }
                }
                net::Event::HandshakeReceived(h) => {
                    if let Some(peer) = state.lock().await.discovery.pool.held(peer_index) {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-peer-connected",
                            slot = peer_index,
                            source = peer.source.as_str(),
                            address = peer.address(),
                            final_slot = h.final_.slot,
                            handshake_ms = elapsed_ms(&started)
                        );
                    }
                    advertisement_revision = 1;
                    handshaken = true;
                    advertised = Some(h.final_.clone());
                    peer_slot = h
                        .leaves
                        .iter()
                        .map(|leaf| leaf.slot)
                        .chain(core::iter::once(h.final_.slot))
                        .max()
                        .unwrap_or(0);
                }
                net::Event::Announcement(a) => {
                    let Some(revision) = advertisement_revision.checked_add(1) else {
                        break 'conn End::Limit;
                    };
                    advertisement_revision = revision;
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-announcement",
                        slot = peer_index,
                        block_slot = a.header.slot,
                        final_slot = a.final_.slot
                    );
                    peer_slot = peer_slot.max(a.header.slot).max(a.final_.slot);
                    if waiting_for_finality.is_some_and(|slot| a.final_.slot > slot) {
                        cursor = Some(state.lock().await.tree.finalized().hash);
                        fallback = true;
                        waiting_for_finality = None;
                    }
                    advertised = Some(a.final_);
                    let s = state.lock().await;
                    if a.header.slot > s.tree.finalized().slot
                        && a.header.encode(params).len() <= s.header_bytes
                        && announcements.len() < REPAIR_LIMIT
                        && !announcements.contains(&a.header)
                    {
                        announcements.push_back(a.header);
                    }
                }
                net::Event::BlockResponse { request_id, blocks } => {
                    let Some((id, request, when, tag)) = requested.take() else {
                        break 'conn End::UnexpectedResponse;
                    };
                    if id != request_id {
                        break 'conn End::UnexpectedResponse;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-block-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "ok",
                        blocks = blocks.len(),
                        bytes = blocks
                            .iter()
                            .map(|block| block.header.encode(params).len() + block.body.len())
                            .sum::<usize>(),
                        elapsed_ms = elapsed_ms(&when)
                    );
                    if *root_probe == Some(request.hash)
                        && request.direction == Direction::DescendingInclusive
                    {
                        *root_probe = None;
                        state.lock().await.root_refusals = None;
                        waiting_for_finality = Some(advertised.as_ref().map_or(0, |f| f.slot));
                        continue;
                    }
                    if let Some(warp) = &mut warp {
                        if request.direction != Direction::DescendingInclusive
                            || request.max_blocks != 1
                        {
                            break 'conn End::UnexpectedResponse;
                        }
                        if let Err(error) =
                            warp.receive_headers(params, blocks, state.lock().await.header_bytes)
                        {
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-warp-rejected",
                                slot = peer_index,
                                step = "head",
                                req = tag.req,
                                error = warp_token(&error)
                            );
                            break 'conn End::WarpRejected;
                        }
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-head-fetched",
                            slot = peer_index,
                            req = tag.req,
                            hash = Hex(&request.hash),
                            block_slot = Opt(warp.head.as_ref().map(|head| head.slot)),
                            authenticated = if warp.finalized.is_some() {
                                "by-fragment"
                            } else {
                                "needs-justification"
                            }
                        );
                        continue;
                    }
                    let mut bytes = 0;
                    for block in blocks {
                        let header_len = block.header.encode(params).len();
                        if header_len > state.lock().await.header_bytes {
                            break 'conn End::Limit;
                        }
                        bytes += header_len + block.body.len();
                        drop(block.body);
                        if request.direction == Direction::DescendingInclusive {
                            let parent = block.header.parent;
                            repair.push(block.header);
                            repair_ready = state.lock().await.tree.get(&parent).is_some();
                            if !repair_ready && repair.len() >= REPAIR_LIMIT {
                                repair.clear();
                            }
                        } else {
                            imports.push_back(block.header);
                        }
                    }
                    if request.direction == Direction::AscendingExclusive {
                        fetch_size.received(bytes);
                    }
                }
                net::Event::WarpResponse {
                    request_id,
                    start_set_id,
                    fragments,
                } => {
                    let Some((id, expected, when, tag)) = warp_requested.take() else {
                        break 'conn End::UnexpectedResponse;
                    };
                    let Some(warp) = &mut warp else {
                        break 'conn End::UnexpectedResponse;
                    };
                    if id != request_id
                        || start_set_id != expected
                        || expected != warp.authorities.set_id()
                    {
                        break 'conn End::UnexpectedResponse;
                    }
                    let limits = {
                        let s = state.lock().await;
                        finality::WarpLimits {
                            max_fragments: 32,
                            max_header_bytes: s.header_bytes,
                            proof: s.proof_limits(),
                        }
                    };
                    let before = warp.fragments;
                    if let Err(error) = warp.advance(params, &fragments, &limits) {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-request-ended",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            outcome = "rejected",
                            start_set_id = start_set_id,
                            bytes = fragments.len(),
                            error = warp_token(&error),
                            elapsed_ms = elapsed_ms(&when)
                        );
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-rejected",
                            slot = peer_index,
                            step = "fragments",
                            req = tag.req,
                            error = warp_token(&error)
                        );
                        break 'conn End::WarpRejected;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-warp-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "ok",
                        start_set_id = start_set_id,
                        bytes = fragments.len(),
                        fragments = warp.fragments.saturating_sub(before),
                        set_id = warp.authorities.set_id(),
                        chain_done = warp.chain_done,
                        elapsed_ms = elapsed_ms(&when)
                    );
                }
                net::Event::JustificationResponse {
                    request_id,
                    target,
                    justification,
                } => {
                    let Some((id, expected, when, tag)) = proof_requested.take() else {
                        break 'conn End::UnexpectedResponse;
                    };
                    if id != request_id || target != expected {
                        break 'conn End::UnexpectedResponse;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-justification-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "ok",
                        bytes = justification.len(),
                        elapsed_ms = elapsed_ms(&when)
                    );
                    let mut s = state.lock().await;
                    if let Some(warp) = &mut warp {
                        if let Err(error) =
                            warp.authenticate(params, &justification, s.proof_limits())
                        {
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-warp-rejected",
                                slot = peer_index,
                                step = "justification",
                                req = tag.req,
                                error = warp_token(&error)
                            );
                            break 'conn End::WarpRejected;
                        }
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-justification-verified",
                            slot = peer_index,
                            req = tag.req,
                            hash = Hex(&target),
                            set_id = warp.authorities.set_id()
                        );
                        continue;
                    }
                    s.proof_owner = None;
                    if let Err(error) = s.finalize(target, &justification) {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-finality-rejected",
                            slot = peer_index,
                            req = tag.req,
                            target = Hex(&target),
                            set_id = s.authorities.set_id(),
                            error = Token(&error)
                        );
                        break 'conn End::FinalityRejected;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-finalized",
                        slot = s.tree.finalized().slot,
                        set_id = s.authorities.set_id(),
                        retained = s.tree.len(),
                        conn = peer_index,
                        req = tag.req,
                        hash = Hex(&s.tree.finalized().hash)
                    );
                }
                net::Event::RequestFailed { request_id, reason }
                    if proof_requested
                        .as_ref()
                        .is_some_and(|(id, ..)| *id == request_id) =>
                {
                    if let Some((_, _, when, tag)) = proof_requested.take() {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-justification-request-ended",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            outcome = "failed",
                            error = alloc::format!("{reason:?}"),
                            elapsed_ms = elapsed_ms(&when)
                        );
                    }
                    if warp.is_some() {
                        break 'conn End::JustificationFailed;
                    }
                    state.lock().await.proof_owner = None;
                }
                net::Event::RequestFailed { request_id, reason }
                    if warp_requested
                        .as_ref()
                        .is_some_and(|(id, ..)| *id == request_id) =>
                {
                    let req = warp_requested.take().map(|(_, _, when, tag)| {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-request-ended",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            outcome = "failed",
                            error = alloc::format!("{reason:?}"),
                            elapsed_ms = elapsed_ms(&when)
                        );
                        tag.req
                    });
                    if reason != net::RequestError::NoData {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-rejected",
                            reason = alloc::format!("{reason:?}"),
                            slot = peer_index,
                            step = "fragments",
                            req = Opt(req)
                        );
                        break 'conn End::WarpFailed;
                    }
                    let Some(warp) = &mut warp else {
                        break 'conn End::UnexpectedResponse;
                    };
                    warp.chain_done = true;
                    if warp.fragments == 0 {
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-warp-fragmentless",
                            reason = "NoData",
                            slot = peer_index,
                            req = Opt(req)
                        );
                    }
                }
                net::Event::RequestFailed { request_id, reason } => {
                    let Some((id, request, when, tag)) = requested.take() else {
                        break 'conn End::UnexpectedResponse;
                    };
                    if id != request_id {
                        break 'conn End::UnexpectedResponse;
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-block-request-ended",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        outcome = "failed",
                        error = alloc::format!("{reason:?}"),
                        elapsed_ms = elapsed_ms(&when)
                    );
                    if warp.is_some() || reason != net::RequestError::NoData {
                        break 'conn End::BlockFailed;
                    }
                    if *root_probe == Some(request.hash)
                        && request.direction == Direction::DescendingInclusive
                    {
                        let mut s = state.lock().await;
                        if let Err(error) = s.refuse_root(peer_index, request.hash) {
                            log!(
                                platform,
                                Warn,
                                log_name,
                                "jam-anchor-unserved",
                                reason = alloc::format!("{reason:?}"),
                                error = alloc::format!("{error}"),
                                hash = alloc::format!("{:?}", request.hash),
                                slot = s.tree.finalized().slot
                            );
                            break 'conn End::AnchorUnserved;
                        }
                        break 'conn End::RootRefused;
                    }
                    if request.direction == Direction::AscendingExclusive {
                        let s = state.lock().await;
                        if request.hash == s.tree.finalized().hash {
                            *root_probe = Some(request.hash);
                            local_progress = true;
                            continue;
                        }
                    }
                    if request.direction == Direction::DescendingInclusive {
                        repair.clear();
                        repair_ready = false;
                    } else if !fallback {
                        cursor = Some(state.lock().await.tree.finalized().hash);
                        fallback = true;
                    } else if request.hash == state.lock().await.tree.finalized().hash {
                        // This peer cannot extend our authenticated root.
                        break 'conn End::RootUnextendable;
                    } else {
                        // First-child selection can repeat a dead branch. Wait for
                        // an announcement repair or for the server to prune it.
                        waiting_for_finality = Some(advertised.as_ref().map_or(0, |f| f.slot));
                    }
                }
                net::Event::ProtocolError(net::ProtocolError::MessageTooLarge) => {
                    if let Some((_, request, _, tag)) = &requested
                        && (request.direction == Direction::AscendingExclusive || warp.is_some())
                    {
                        let before = fetch_size.count;
                        fetch_size.oversized();
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-block-size-halved",
                            slot = peer_index,
                            req = tag.req,
                            max_blocks = before,
                            next_max_blocks = fetch_size.count,
                            ceiling = fetch_size.ceiling
                        );
                    }
                    break 'conn End::MessageTooLarge;
                }
                net::Event::ProtocolError(error) => {
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-peer-protocol-error",
                        slot = peer_index,
                        error = Token(&error)
                    );
                    break 'conn End::ProtocolError;
                }
            }
        }
        if handshaken && !warped {
            if warp.is_none() {
                warp = state.lock().await.reserve_warp(peer_index);
            }
            if let Some(w) = &mut warp {
                if !w.chain_done && warp_requested.is_none() {
                    let start = w.authorities.set_id();
                    let Ok(id) = connection.request_warp(start) else {
                        break 'conn End::RequestRefused;
                    };
                    let tag = Tag::new("warp-join");
                    warp_requested = Some((id, start, now.clone(), tag));
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-warp-request-queued",
                        set_id = start,
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose
                    );
                    local_progress = true;
                } else if w.chain_done {
                    if w.fragments == 0 {
                        let mut s = state.lock().await;
                        s.warp_owner = None;
                        if let Err(error) = s.stop_if_unserved() {
                            log!(
                                platform,
                                Warn,
                                log_name,
                                "jam-anchor-unserved",
                                reason = "NoData",
                                error = alloc::format!("{error}"),
                                slot = s.tree.finalized().slot
                            );
                            break 'conn End::AnchorUnserved;
                        }
                        warp = None;
                        warped = true;
                        local_progress = true;
                    } else {
                        if w.final_head.is_none() {
                            // Freeze the latest advertisement processed when CE153
                            // pagination completes, not subsequent announcements.
                            w.final_head = advertised.clone();
                            if let Some(f) = &w.final_head {
                                log!(
                                    platform,
                                    Debug,
                                    log_name,
                                    "jam-warp-join-selected",
                                    advertisement = advertisement_revision,
                                    slot = f.slot,
                                    conn = peer_index,
                                    hash = Hex(&f.hash),
                                    fragments = w.fragments,
                                    set_id = w.authorities.set_id()
                                );
                            }
                        }
                        if w.head.is_none() && requested.is_none() {
                            let Some(f) = &w.final_head else {
                                break 'conn End::WarpInvalid;
                            };
                            // F alone: the read is at F against its signed root.
                            let request = BlockRequest {
                                hash: f.hash,
                                direction: Direction::DescendingInclusive,
                                max_blocks: 1,
                            };
                            let Ok(id) = connection.request_blocks(request.clone()) else {
                                break 'conn End::RequestRefused;
                            };
                            let tag = Tag::new("warp-join-head");
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-block-request-queued",
                                slot = peer_index,
                                req = tag.req,
                                purpose = tag.purpose,
                                hash = Hex(&request.hash),
                                direction = direction_str(&request.direction),
                                max_blocks = request.max_blocks
                            );
                            requested = Some((id, request, now.clone(), tag));
                            local_progress = true;
                        } else if w.head.is_some()
                            && w.finalized.is_none()
                            && proof_requested.is_none()
                        {
                            let Some(f) = &w.final_head else {
                                break 'conn End::WarpInvalid;
                            };
                            let Ok(id) = connection.request_justification(f.hash) else {
                                break 'conn End::RequestRefused;
                            };
                            let tag = Tag::new("warp-join");
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-justification-request-queued",
                                slot = peer_index,
                                req = tag.req,
                                purpose = tag.purpose,
                                target = Hex(&f.hash),
                                target_slot = f.slot
                            );
                            proof_requested = Some((id, f.hash, now.clone(), tag));
                            local_progress = true;
                        } else if w.finalized.is_some() {
                            if let Some(rx) = &mut w.read {
                                match rx.try_recv() {
                                    Ok(Some(Ok(result))) => {
                                        let Ok(expected) = w.next_read() else {
                                            break 'conn End::WarpInvalid;
                                        };
                                        if result.at != expected.at
                                            || result.root != expected.root
                                            || result.trust != Trust::Finalized
                                            || result.root_header != expected.root_header
                                        {
                                            break 'conn End::WarpInvalid;
                                        }
                                        let before = w.items.len();
                                        for index in [4, 6, 8, 11].into_iter().skip(before) {
                                            let key = trie::state_key(index);
                                            if key > result.range.complete_to {
                                                break;
                                            }
                                            let Some((_, value)) = result
                                                .range
                                                .entries
                                                .iter()
                                                .find(|(k, _)| *k == key)
                                            else {
                                                break 'conn End::WarpInvalid;
                                            };
                                            w.items.push((key, value.clone()));
                                            log!(
                                                platform,
                                                Debug,
                                                log_name,
                                                "jam-warp-item-read",
                                                slot = peer_index,
                                                item = index,
                                                bytes = value.len()
                                            );
                                        }
                                        if w.items.len() == before {
                                            break 'conn End::WarpInvalid;
                                        }
                                        w.state_responses += 1;
                                        w.read = None;
                                        local_progress = true;
                                    }
                                    Ok(None) => {}
                                    Ok(Some(Err(StateReadError::Unavailable))) => {
                                        log!(
                                            platform,
                                            Debug,
                                            log_name,
                                            "jam-state-unavailable",
                                            slot = peer_index,
                                            purpose = "warp-join"
                                        );
                                        break 'conn End::StateUnavailable;
                                    }
                                    Err(_) => break 'conn End::StateCancelled,
                                }
                            }
                            if w.items.len() == 4 {
                                let Some(w) = warp.take() else {
                                    break 'conn End::WarpInvalid;
                                };
                                let count = w.fragments;
                                let fragment_finality = w.last_final.is_some_and(|last| {
                                    w.final_head
                                        .as_ref()
                                        .is_some_and(|f| f.hash == last.hash && f.slot == last.slot)
                                });
                                let state_responses = w.state_responses;
                                let state_bytes: usize =
                                    w.items.iter().map(|(_, value)| value.len()).sum();
                                let mut s = state.lock().await;
                                if let Err(error) = s.apply_warp(peer_index, w) {
                                    log!(
                                        platform,
                                        Debug,
                                        log_name,
                                        "jam-warp-rejected",
                                        slot = peer_index,
                                        step = "apply",
                                        error = warp_token(&error)
                                    );
                                    break 'conn End::WarpRejected;
                                }
                                warp_revision = s.warp_revision;
                                fetch_size.count =
                                    params.epoch_len.clamp(1, 64).min(fetch_size.ceiling);
                                cursor = Some(s.tree.finalized().hash);
                                *root_probe = None;
                                fallback = true;
                                waiting_for_finality = None;
                                repair.clear();
                                imports.clear();
                                announcements.clear();
                                warped = true;
                                local_progress = true;
                                log!(
                                    platform,
                                    Debug,
                                    log_name,
                                    "jam-warp-applied",
                                    set_id = s.authorities.set_id(),
                                    slot = s.tree.finalized().slot,
                                    fragments = count,
                                    state_bytes = state_bytes,
                                    state_responses = state_responses,
                                    fragment_finality = fragment_finality,
                                    conn = peer_index,
                                    hash = Hex(&s.tree.finalized().hash)
                                );
                            } else if w.read.is_none() {
                                let Ok(read) = w.next_read() else {
                                    break 'conn End::WarpInvalid;
                                };
                                let mut s = state.lock().await;
                                match s.reads.start(read) {
                                    Ok(rx) => {
                                        w.read = Some(rx);
                                        local_progress = true;
                                    }
                                    Err(net::Error::Limit) => {}
                                    Err(_) => break 'conn End::WarpInvalid,
                                }
                            }
                        }
                    }
                }
            }
        }
        let normal_sync = warped && state.lock().await.warp_owner.is_none();
        let pause_imports = {
            let s = state.lock().await;
            if normal_sync && s.tree.len() >= s.max_blocks && s.proof_owner.is_none() {
                break 'conn End::TreeFull;
            }
            !normal_sync || (s.proof_owner.is_some() && s.tree.len() + 1 >= s.max_blocks)
        };
        if !pause_imports && !imports.is_empty() {
            if let Some(header) = imports.pop_front() {
                let hash = header.hash(params);
                let block_slot = header.slot;
                let mut s = state.lock().await;
                let known = s.tree.get(&hash).is_some();
                // Another peer may have finalized this prefix while the batch
                // was in flight. Its pruned ancestors need no re-import.
                let result = if header.slot <= s.tree.finalized().slot {
                    Ok(())
                } else {
                    s.insert(header, platform.now_from_unix_epoch().as_secs())
                };
                match result {
                    Ok(()) => {
                        cursor = fallback.then_some(hash);
                        last_activity = now.clone();
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-header-inserted",
                            slot = peer_index,
                            via = "ascending",
                            block_slot = block_slot,
                            hash = Hex(&hash),
                            known = known || block_slot <= s.tree.finalized().slot
                        );
                    }
                    Err(InsertFailure::Tree(tree::InsertError::Verify(_))) if !fallback => {
                        imports.clear();
                        cursor = Some(s.tree.finalized().hash);
                        fallback = true;
                    }
                    Err(_) => break 'conn End::InsertFailed,
                }
                local_progress = true;
            }
        } else if !pause_imports && requested.is_none() {
            let (header, via) = if repair_ready {
                (repair.pop(), "repair")
            } else if repair.is_empty() {
                (announcements.pop_front(), "announcement")
            } else {
                (None, "")
            };
            if let Some(header) = header {
                let mut s = state.lock().await;
                if header.slot > s.tree.finalized().slot {
                    let hash = header.hash(params);
                    let known = s.tree.get(&hash).is_some();
                    match s.insert(header.clone(), platform.now_from_unix_epoch().as_secs()) {
                        Ok(()) => {
                            cursor = None;
                            fallback = false;
                            waiting_for_finality = None;
                            last_activity = now.clone();
                            log!(
                                platform,
                                Debug,
                                log_name,
                                "jam-header-inserted",
                                slot = peer_index,
                                via = via,
                                block_slot = header.slot,
                                hash = Hex(&hash),
                                known = known
                            );
                        }
                        Err(InsertFailure::Tree(tree::InsertError::UnknownParent)) => {
                            // Finality from another peer may have pruned the
                            // parent since the repair was marked ready.
                            repair_ready = false;
                            repair.push(header);
                            if repair.len() >= REPAIR_LIMIT {
                                repair.clear();
                            }
                        }
                        Err(_) => break 'conn End::InsertFailed,
                    }
                }
                repair_ready = !repair.is_empty() && repair_ready;
                local_progress = true;
            }
        }
        if normal_sync {
            let event = state
                .lock()
                .await
                .discovery_turn(platform.now_from_unix_epoch());
            match event {
                Some(DiscoveryEvent::Started { slot }) => {
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-discovery-read-started",
                        slot = slot
                    );
                    local_progress = true;
                }
                Some(DiscoveryEvent::Refreshed {
                    merge,
                    value_bytes,
                    elapsed_ms,
                }) => {
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-pool-changed",
                        validators = merge.validators,
                        usable = merge.usable,
                        discovered = merge.discovered,
                        added = merge.added,
                        removed = merge.removed,
                        retired = merge.retired,
                        value_bytes = value_bytes,
                        elapsed_ms = elapsed_ms
                    );
                }
                Some(DiscoveryEvent::Failed { reason }) => {
                    if reason == "Unavailable" {
                        // Every slot was tried: the read's own outcome.
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-state-unavailable",
                            slot = "-",
                            purpose = "discovery"
                        );
                    }
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-discovery-failed",
                        reason = reason
                    );
                }
                None => {}
            }
        }
        if handshaken
            && normal_sync
            && proof_requested.is_none()
            && state_requested.is_none()
            && let Some(advertised) = &advertised
        {
            let mut s = state.lock().await;
            if let Some(target) = s.reserve_proof(peer_index, advertised) {
                let Ok(id) = connection.request_justification(target) else {
                    break 'conn End::RequestRefused;
                };
                let tag = Tag::new("finality");
                proof_requested = Some((id, target, platform.now(), tag));
                local_progress = true;
                log!(
                    platform,
                    Debug,
                    log_name,
                    "jam-justification-request-queued",
                    slot = peer_index,
                    req = tag.req,
                    purpose = tag.purpose,
                    target = Hex(&target),
                    target_slot = Opt(s.tree.get(&target).map(|block| block.slot)),
                    set_id = s.authorities.set_id()
                );
            }
        }
        // Finality and state reads arbitrate the second slot; never enqueue a
        // third request into the connection's two-request budget.
        if handshaken
            && state_requested.is_none()
            && proof_requested.is_none()
            && warp_requested.is_none()
        {
            let mut s = state.lock().await;
            if !s.stopped
                && s.warp_owner.is_none_or(|owner| owner == peer_index)
                && let Some(request) = s.reads.reserve(peer_index)
            {
                let trust = s.reads.pending.as_ref().map(|(read, _)| read.trust);
                let keys = alloc::format!("{}", Keys(&request));
                let block = request.block;
                let max_size = request.max_size;
                match connection.request_state(request) {
                    Ok(id) => {
                        let tag = Tag::new(trust.map_or("-", read_purpose));
                        state_requested = Some((id, platform.now(), tag));
                        local_progress = true;
                        log!(
                            platform,
                            Debug,
                            log_name,
                            "jam-state-request-queued",
                            slot = peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            block = Hex(&block),
                            trust = Opt(trust.map(trust_str)),
                            keys = keys,
                            max_size = max_size
                        );
                    }
                    Err(_) => {
                        s.reads.release(peer_index, true);
                        break 'conn End::RequestRefused;
                    }
                }
            }
        }
        if handshaken && normal_sync && requested.is_none() && !repair_ready && imports.is_empty() {
            let s = state.lock().await;
            if s.tree.len() + 1 >= s.max_blocks && s.proof_owner.is_some() {
                // The proof already in flight must get a turn before more imports.
            } else if s.tree.len() >= s.max_blocks && s.proof_owner.is_none() {
                // All proof candidates failed: don't deadlock on an unfinalizable fork.
                break 'conn End::TreeFull;
            } else {
                let request = if let Some(hash) = *root_probe {
                    Some((
                        BlockRequest {
                            hash,
                            direction: Direction::DescendingInclusive,
                            max_blocks: 1,
                        },
                        "root-probe",
                    ))
                } else if let Some(header) = repair.last() {
                    Some((
                        BlockRequest {
                            hash: header.parent,
                            direction: Direction::DescendingInclusive,
                            max_blocks: 1,
                        },
                        "repair",
                    ))
                } else if waiting_for_finality.is_none() && announcements.is_empty() {
                    let head = cursor
                        .and_then(|hash| s.tree.get(&hash))
                        .unwrap_or_else(|| s.tree.best());
                    (peer_slot > head.slot).then_some((
                        BlockRequest {
                            hash: head.hash,
                            direction: Direction::AscendingExclusive,
                            max_blocks: fetch_size.count,
                        },
                        "ascending",
                    ))
                } else {
                    None
                };
                if let Some((request, purpose)) = request {
                    let Ok(id) = connection.request_blocks(request.clone()) else {
                        break 'conn End::RequestRefused;
                    };
                    let tag = Tag::new(purpose);
                    let (hash, direction, max_blocks) = (
                        request.hash,
                        direction_str(&request.direction),
                        request.max_blocks,
                    );
                    requested = Some((id, request, platform.now(), tag));
                    local_progress = true;
                    log!(
                        platform,
                        Debug,
                        log_name,
                        "jam-block-request-queued",
                        slot = peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        hash = Hex(&hash),
                        direction = direction,
                        max_blocks = max_blocks
                    );
                }
            }
        }
        // Wake for substreams, transport buffer progress, or bounded protocol deadlines.
        let next = future::or(
            async { Some(platform.next_substream(&mut transport).await) },
            async {
                // B2 can leave buffered input after an event, or need another call
                // after committing FIN. No new platform edge is promised for that
                // work. Poll substreams above, then cooperatively drive again.
                if local_progress
                    || ((repair_ready || !imports.is_empty()) && !pause_imports)
                    || (!pause_imports && requested.is_none() && !announcements.is_empty())
                {
                    return None;
                }
                future::or(
                    async {
                        let mut waits = futures_util::stream::FuturesUnordered::new();
                        for stream in &mut streams {
                            waits.push(platform.wait_read_write_again(stream.stream.as_mut()));
                        }
                        if waits.next().await.is_none() {
                            future::pending::<()>().await;
                        }
                    },
                    platform.sleep(Duration::from_millis(100)),
                )
                .await;
                None
            },
        )
        .await;
        match next {
            Some(Some((stream, direction))) => {
                let Some(id) = next_id.checked_add(1) else {
                    break 'conn End::Limit;
                };
                next_id = id;
                let mut request = None;
                let limited_lifetime = match direction {
                    SubstreamDirection::Outbound => {
                        let Some((kind, _)) = opening.take() else {
                            break 'conn End::ProtocolError;
                        };
                        request = match kind {
                            net::SubstreamKind::Ce128 { request_id }
                            | net::SubstreamKind::Ce129 { request_id }
                            | net::SubstreamKind::Ce130 { request_id }
                            | net::SubstreamKind::Ce153 { request_id } => Some(request_id),
                            _ => None,
                        };
                        if connection.substream_opened(id, kind).is_err() {
                            let _ = connection.outgoing_open_failed(kind);
                            break 'conn End::ProtocolError;
                        }
                        matches!(
                            kind,
                            net::SubstreamKind::Ce128 { .. }
                                | net::SubstreamKind::Ce129 { .. }
                                | net::SubstreamKind::Ce130 { .. }
                                | net::SubstreamKind::Ce153 { .. }
                        )
                    }
                    SubstreamDirection::Inbound => {
                        if connection.substream_incoming(id).is_err() {
                            continue;
                        }
                        true
                    }
                };
                streams.push(Stream {
                    id,
                    stream: Box::pin(stream),
                    opened: platform.now(),
                    limited_lifetime,
                    request,
                });
            }
            Some(None) => break 'conn End::Transport,
            None => {}
        }
    };
    // Requests still in flight end with the connection: say how, once each.
    let outcome = |timeout: End| {
        if end == timeout {
            "timeout"
        } else {
            "cancelled"
        }
    };
    let pending = [
        requested
            .as_ref()
            .map(|(_, _, when, tag)| ("jam-block-request-ended", when, tag, End::BlockTimeout)),
        proof_requested.as_ref().map(|(_, _, when, tag)| {
            (
                "jam-justification-request-ended",
                when,
                tag,
                End::JustificationTimeout,
            )
        }),
        state_requested
            .as_ref()
            .map(|(_, when, tag)| ("jam-state-request-ended", when, tag, End::StateTimeout)),
        warp_requested
            .as_ref()
            .map(|(_, _, when, tag)| ("jam-warp-request-ended", when, tag, End::WarpTimeout)),
    ];
    for (name, when, tag, timeout) in pending.into_iter().flatten() {
        log!(
            platform,
            Debug,
            log_name,
            name,
            slot = peer_index,
            req = tag.req,
            purpose = tag.purpose,
            outcome = outcome(timeout),
            reason = end.as_str(),
            elapsed_ms = elapsed_ms(when)
        );
    }
    // A rejection already said where the join failed.
    if let Some(w) = &warp
        && !matches!(end, End::WarpRejected | End::WarpFailed)
    {
        log!(
            platform,
            Debug,
            log_name,
            "jam-warp-abandoned",
            slot = peer_index,
            step = warp_step(w),
            fragments = w.fragments,
            reason = end.as_str()
        );
    }
    end
}

mod discovery;

#[cfg(all(test, feature = "std"))]
mod tests;

#[cfg(test)]
mod log_format_tests {
    use super::{End, Hex, Key, Keys, Opt, Token, finality, net, trie};
    use alloc::string::ToString as _;
    use smoldot::jam::codec::DecodeError;

    #[test]
    fn tokens_are_variant_paths_without_separators() {
        let wrong = finality::Error::WrongSetId {
            expected: 1,
            received: 2,
        };
        assert_eq!(Token(&wrong).to_string(), "WrongSetId");
        let decode = finality::Error::Decode(DecodeError::LengthLimit);
        assert_eq!(Token(&decode).to_string(), "Decode(LengthLimit)");
        let item = net::ProtocolError::Decode(DecodeError::InvalidDiscriminant(3));
        assert_eq!(Token(&item).to_string(), "Decode(InvalidDiscriminant(3))");
        assert_eq!(
            Token(&trie::ProofError::RootMismatch).to_string(),
            "RootMismatch"
        );
    }

    #[test]
    fn values_are_single_tokens() {
        assert_eq!(Hex(&[0xab, 0x01]).to_string(), "0xab01");
        assert_eq!(Opt::<u64>(None).to_string(), "-");
        assert_eq!(Opt(Some(7)).to_string(), "7");
        assert_eq!(Key(&trie::state_key(8)).to_string(), "C8");
        let mut odd = trie::state_key(8);
        odd[30] = 1;
        assert!(Key(&odd).to_string().starts_with("0x08"));
        let request = trie::StateRequest {
            block: [0; 32],
            start: trie::state_key(4),
            end: trie::state_key(11),
            max_size: 1,
        };
        assert_eq!(Keys(&request).to_string(), "C4..C11");
        assert_eq!(End::JustificationTimeout.as_str(), "justification-timeout");
    }
}
