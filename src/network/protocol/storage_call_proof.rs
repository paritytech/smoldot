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

use crate::util::protobuf;

use alloc::vec::Vec;

/// Description of a storage proof request that can be sent to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProofRequestConfig<TKeysIter> {
    /// Hash of the block to request the storage of.
    pub block_hash: [u8; 32],
    /// List of storage keys to query.
    pub keys: TKeysIter,
}

// See https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/client/network/sync/src/schema/api.v1.proto
// for protocol definition.

/// Builds the bytes corresponding to a storage proof request.
pub fn build_storage_proof_request<'a>(
    config: StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + 'a>,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    protobuf::message_tag_encode(
        2,
        protobuf::bytes_tag_encode(2, config.block_hash)
            .map(either::Left)
            .chain(
                config
                    .keys
                    .flat_map(|key| protobuf::bytes_tag_encode(3, key))
                    .map(either::Right),
            ),
    )
}

/// Description of a call proof request that can be sent to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallProofRequestConfig<'a, I> {
    /// Hash of the block to request the storage of.
    pub block_hash: [u8; 32],
    /// Name of the runtime function to call.
    pub method: &'a str,
    /// Iterator to buffers of bytes to be concatenated then passed as input to the call. The
    /// semantics of these bytes depend on which method is being called.
    pub parameter_vectored: I,
}

// See https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/client/network/light/src/schema/light.v1.proto
// for protocol definition.

/// Builds the bytes corresponding to a call proof request.
pub fn build_call_proof_request<'a>(
    config: CallProofRequestConfig<'a, impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a>,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    // TODO: don't allocate here
    let parameter = config
        .parameter_vectored
        .fold(Vec::with_capacity(512), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

    protobuf::message_tag_encode(
        1,
        protobuf::bytes_tag_encode(2, config.block_hash)
            .map(either::Left)
            .chain(
                protobuf::string_tag_encode(3, config.method)
                    .map(either::Left)
                    .map(either::Right),
            )
            .chain(
                protobuf::bytes_tag_encode(4, parameter)
                    .map(either::Right)
                    .map(either::Right),
            ),
    )
}

/// Decodes a response to a storage proof request or a call proof request.
///
/// On success, returns a SCALE-encoded Merkle proof, or `None` if the remote couldn't answer
/// the request.
pub fn decode_storage_or_call_proof_response(
    ty: StorageOrCallProof,
    response_bytes: &[u8],
) -> Result<Option<&[u8]>, DecodeStorageCallProofResponseError> {
    let field_num = match ty {
        StorageOrCallProof::CallProof => 1,
        StorageOrCallProof::StorageProof => 2,
    };

    // TODO: while the `proof` field is correctly optional, the `response` field isn't supposed to be optional; make it `#[required]` again once https://github.com/paritytech/substrate/pull/12732 has been merged and released

    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            #[optional] response = field_num => protobuf::message_tag_decode(protobuf::message_decode!{
                #[optional] proof = 2 => protobuf::bytes_tag_decode
            }),
        }),
    );

    let proof = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, out)) => out.response.and_then(|r| r.proof),
        Err(_) => return Err(DecodeStorageCallProofResponseError::ProtobufDecode),
    };

    Ok(proof)
}

/// Error potentially returned by [`decode_storage_or_call_proof_response`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum DecodeStorageCallProofResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
    /// Response isn't a response to a storage proof request.
    BadResponseTy,
    /// Failed to decode response as a storage proof.
    ProofDecodeError,
}

/// Passed as parameter to [`decode_storage_or_call_proof_response`] to indicate what kind of
/// request the response corresponds to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum StorageOrCallProof {
    StorageProof,
    CallProof,
}
