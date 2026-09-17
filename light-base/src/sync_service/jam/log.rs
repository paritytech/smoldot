// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The driver's debug events: the macros that log them, request tags, value
//! formats, and why a connection ended.

// Debug events. Every log line of this driver is one event:
//
//     jam-<area>-<what>[; key=value, key=value, ...]
//
// logged at `Debug`. A value is one token without `, ` or `=` (see
// [`Token`]). `slot=` is the connection slot. `req=` ties together the lines
// about one request; its outcome line adds `outcome=` and `elapsed_ms=`.

use crate::platform::PlatformRef;
use core::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};
use smoldot::jam::types::Direction;

/// Logs one event of the connection `$conn`, at `Debug`.
macro_rules! event {
    ($conn:expr, $($fields:tt)*) => {
        log!($conn.platform, Debug, $conn.log_name, $($fields)*)
    };
}

/// The outcome line of a request: `slot`, `req`, `purpose`, `outcome`, the
/// given fields, then `elapsed_ms`.
macro_rules! request_ended {
    ($conn:expr, $name:expr, $request:expr, $outcome:expr $(, $($fields:tt)*)?) => {
        event!(
            $conn,
            $name,
            slot = $conn.peer_index,
            req = $request.tag.req,
            purpose = $request.tag.purpose,
            outcome = $outcome,
            $($($fields)*,)?
            elapsed_ms = super::log::elapsed_ms($conn.platform, &$request.queued)
        )
    };
}

pub(super) use {event, request_ended};

/// Milliseconds since `when`.
pub(super) fn elapsed_ms<P: PlatformRef>(platform: &P, when: &P::Instant) -> u128 {
    (platform.now() - when.clone()).as_millis()
}

/// The counter behind `req=`, per process. It only labels log lines, so it
/// wraps around instead of needing 64-bit atomics, which some targets lack.
static NEXT_REQUEST: AtomicU32 = AtomicU32::new(1);

fn next_request() -> u32 {
    NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
}

/// A request's log identity: its `req=` and what it is for.
#[derive(Clone, Copy)]
pub(super) struct Tag {
    pub(super) req: u32,
    pub(super) purpose: &'static str,
}

impl Tag {
    pub(super) fn new(purpose: &'static str) -> Self {
        Self {
            req: next_request(),
            purpose,
        }
    }
}

/// `0x` and the bytes in lowercase hex.
pub(super) struct Hex<'a>(pub(super) &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// An error's variant path as one token: its `Debug` output without
/// whitespace and without the fields of struct variants, for example
/// `Decode(LengthLimit)` or `WrongSetId`.
pub(super) struct Token<'a>(pub(super) &'a dyn fmt::Debug);

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

pub(super) fn direction_str(direction: &Direction) -> &'static str {
    match direction {
        Direction::AscendingExclusive => "ascending",
        Direction::DescendingInclusive => "descending",
    }
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "kebab-case")]
pub(super) enum End {
    Setup,
    HandshakeTimeout,
    Idle,
    StreamOpenTimeout,
    BlockTimeout,
    StreamTimeout,
    StreamReset,
    Transport,
    Limit,
    UnexpectedResponse,
    RootUnextendable,
    MessageTooLarge,
    ProtocolError,
    RequestRefused,
    InsertFailed,
}

impl End {
    pub(super) fn as_str(self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{Hex, Token};
    use alloc::string::ToString as _;
    use smoldot::jam::{codec::DecodeError, net};

    #[test]
    fn tokens_are_variant_paths_without_separators() {
        let item = net::ProtocolError::Decode(DecodeError::InvalidDiscriminant(3));
        assert_eq!(Token(&item).to_string(), "Decode(InvalidDiscriminant(3))");
    }

    #[test]
    fn values_are_single_tokens() {
        assert_eq!(Hex(&[0xab, 0x01]).to_string(), "0xab01");
    }
}
