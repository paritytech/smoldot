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

use crate::network_service::BroadcastStatementResult;
use alloc::vec::Vec;
use smoldot::json_rpc::methods::StatementSubmitResult;
use smoldot::network::codec;

/// Validates a SCALE-encoded statement and broadcasts it to the network.
///
/// Returns the appropriate [`StatementSubmitResult`] based on the decode and broadcast outcome.
/// The `broadcast` closure is only called if the statement is valid.
pub async fn validate_and_broadcast_statement<F, Fut>(
    encoded: &[u8],
    broadcast: F,
) -> StatementSubmitResult
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = BroadcastStatementResult>,
{
    if codec::decode_statement(encoded).is_err() {
        return StatementSubmitResult::Invalid {
            reason: "Invalid statement encoding".into(),
        };
    }

    let broadcasted = broadcast(encoded.to_vec()).await;
    if broadcasted.total == 0 {
        StatementSubmitResult::InternalError {
            error: "No connected peers".into(),
        }
    } else {
        StatementSubmitResult::New
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    fn valid_statement() -> Vec<u8> {
        codec::encode_statement(&codec::Statement {
            proof: None,
            decryption_key: None,
            expiry: 42,
            channel: None,
            topics: Vec::new(),
            data: None,
        })
        .unwrap()
    }

    #[test]
    fn validate_and_broadcast_invalid_encoding() {
        let result = block_on(validate_and_broadcast_statement(&[0xff, 0xff], |_| async {
            unreachable!()
        }));
        assert_eq!(
            result,
            StatementSubmitResult::Invalid {
                reason: "Invalid statement encoding".into()
            }
        );
    }

    #[test]
    fn validate_and_broadcast_no_peers() {
        let result = block_on(validate_and_broadcast_statement(
            &valid_statement(),
            |_| async {
                BroadcastStatementResult { sent: 0, total: 0 }
            },
        ));
        assert_eq!(
            result,
            StatementSubmitResult::InternalError {
                error: "No connected peers".into()
            }
        );
    }

    #[test]
    fn validate_and_broadcast_new() {
        let result = block_on(validate_and_broadcast_statement(
            &valid_statement(),
            |_| async {
                BroadcastStatementResult { sent: 3, total: 5 }
            },
        ));
        assert_eq!(result, StatementSubmitResult::New);
    }
}
