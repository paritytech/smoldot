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
    let parameter = config.parameter_vectored.fold(Vec::new(), |mut a, b| {
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

/// Decodes a response to a call proof request.
// TODO: should have a more zero-cost API
pub fn decode_call_proof_response(
    response_bytes: &[u8],
) -> Result<Vec<Vec<u8>>, DecodeCallProofResponseError> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        protobuf::message_decode((protobuf::message_tag_decode(
            1,
            protobuf::message_decode((protobuf::bytes_tag_decode(2),)),
        ),)),
    );

    let proof: &[u8] = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, ((((b,),),),))) => b,
        Err(_) => return Err(DecodeCallProofResponseError::ProtobufDecode),
    };

    // The proof itself is a SCALE-encoded `Vec<Vec<u8>>`.
    // Each inner `Vec<u8>` is a node value in the storage trie.
    let (_, decoded) = nom::combinator::all_consuming(nom::combinator::flat_map(
        crate::util::nom_scale_compact_usize,
        |num_elems| {
            nom::multi::many_m_n(
                num_elems,
                num_elems,
                nom::combinator::map(crate::util::nom_bytes_decode, |b| b.to_vec()),
            )
        },
    ))(proof)
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        DecodeCallProofResponseError::ProofDecodeError
    })?;

    Ok(decoded)
}

/// Error potentially returned by [`decode_call_proof_response`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum DecodeCallProofResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
    /// Response isn't a response to a call proof request.
    BadResponseTy,
    /// Failed to decode response as a call proof.
    ProofDecodeError,
}
