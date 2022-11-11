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

use super::methods;

/// Produces the input to pass to the `TransactionPaymentApi_query_info` runtime call.
pub fn payment_info_parameters(
    extrinsic: &'_ [u8],
) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + Clone + '_ {
    [
        either::Left(extrinsic),
        either::Right(u32::try_from(extrinsic.len()).unwrap().to_le_bytes()),
    ]
    .into_iter()
}

/// Name of the runtime function to call in order to obtain the payment fees.
pub const PAYMENT_FEES_FUNCTION_NAME: &str = "TransactionPaymentApi_query_info";

/// Attempt to decode the output of the runtime call.
///
/// Must be passed the version of the `TransactionPaymentApi` API, according to the runtime
/// specification.
pub fn decode_payment_info(
    scale_encoded: &'_ [u8],
    api_version: u32,
) -> Result<methods::RuntimeDispatchInfo, DecodeError> {
    let is_api_v2 = match api_version {
        1 => false,
        2 => true,
        _ => return Err(DecodeError::UnknownRuntimeVersion),
    };

    match nom::combinator::all_consuming(nom_decode_payment_info::<nom::error::Error<&'_ [u8]>>(
        is_api_v2,
    ))(scale_encoded)
    {
        Ok((_, info)) => Ok(info),
        Err(_) => Err(DecodeError::ParseError),
    }
}

/// Potential error when decoding payment information runtime output.
#[derive(Debug, derive_more::Display)]
pub enum DecodeError {
    /// Failed to parse the return value of `TransactionPaymentApi_query_info`.
    ParseError,
    /// The `TransactionPaymentApi` API uses a version that smoldot doesn't support.
    UnknownRuntimeVersion,
}

fn nom_decode_payment_info<'a, E: nom::error::ParseError<&'a [u8]>>(
    is_api_v2: bool,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], methods::RuntimeDispatchInfo, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            move |bytes| {
                if is_api_v2 {
                    nom::number::complete::le_u64(bytes)
                } else {
                    nom::combinator::map(
                        nom::sequence::tuple((
                            crate::util::nom_scale_compact_u64,
                            crate::util::nom_scale_compact_u64,
                        )),
                        |(ref_time, _proof_size)| ref_time,
                    )(bytes)
                }
            },
            nom::combinator::map_opt(nom::number::complete::u8, |n| match n {
                0 => Some(methods::DispatchClass::Normal),
                1 => Some(methods::DispatchClass::Operational),
                2 => Some(methods::DispatchClass::Mandatory),
                _ => None,
            }),
            |bytes| {
                // The exact format here is the SCALE encoding of the type `Balance`.
                // Normally, determining the actual type of `Balance` would require parsing the
                // metadata provided by the runtime. However, this is a pretty difficult to
                // implement and CPU-heavy. Instead, given that there is no other field after
                // the balance, we simply parse all the remaining bytes.
                // Because the SCALE encoding of a number is the number in little endian format,
                // we decode the bytes in little endian format in a way that works no matter the
                // number of bytes.
                // If a field was to be added after the balance, this code would need to be
                // modified.
                // TODO: must make sure that TransactionPaymentApi is at version 1, see https://github.com/paritytech/smoldot/issues/949
                let mut num = 0u128;
                let mut shift = 0u32;
                for byte in <[u8]>::iter(bytes) {
                    let shifted =
                        u128::from(*byte)
                            .checked_mul(1 << shift)
                            .ok_or(nom::Err::Error(nom::error::make_error(
                                bytes,
                                nom::error::ErrorKind::Digit,
                            )))?;
                    num =
                        num.checked_add(shifted)
                            .ok_or(nom::Err::Error(nom::error::make_error(
                                bytes,
                                nom::error::ErrorKind::Digit,
                            )))?;
                    shift =
                        shift
                            .checked_add(16)
                            .ok_or(nom::Err::Error(nom::error::make_error(
                                bytes,
                                nom::error::ErrorKind::Digit,
                            )))?;
                }

                Ok((&[][..], num))
            },
        )),
        |(weight, class, partial_fee)| methods::RuntimeDispatchInfo {
            weight,
            class,
            partial_fee,
        },
    )
}
