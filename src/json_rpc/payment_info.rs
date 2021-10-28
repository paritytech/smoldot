// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

use core::iter;

/// Produces the input to pass to the `TransactionPaymentApi_query_info` runtime call.
pub fn payment_info_parameters(
    extrinsic: &'_ [u8],
) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + Clone + '_ {
    iter::once(either::Left(extrinsic))
        .chain(iter::once(u32::try_from(extrinsic.len()).unwrap().to_le_bytes()).map(either::Right))
}

/// Name of the runtime function to call in order to obtain the payment fees.
pub const PAYMENT_FEES_FUNCTION_NAME: &str = "TransactionPaymentApi_query_info";

/// Attempt to decode the output of the runtime call.
pub fn decode_payment_info(
    scale_encoded: &'_ [u8],
) -> Result<methods::RuntimeDispatchInfo, DecodeError> {
    match nom::combinator::all_consuming(nom_decode_payment_info::<nom::error::Error<&'_ [u8]>>)(
        scale_encoded,
    ) {
        Ok((_, info)) => Ok(info),
        Err(_) => Err(DecodeError()),
    }
}

/// Potential error when decoding payment information runtime output.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Payment info parsing error")]
pub struct DecodeError();

fn nom_decode_payment_info<'a, E: nom::error::ParseError<&'a [u8]>>(
    value: &'a [u8],
) -> nom::IResult<&'a [u8], methods::RuntimeDispatchInfo, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u64,
            nom::combinator::map_opt(nom::number::complete::u8, |n| match n {
                0 => Some(methods::DispatchClass::Normal),
                1 => Some(methods::DispatchClass::Operational),
                2 => Some(methods::DispatchClass::Mandatory),
                _ => None,
            }),
            // TODO: this is actually of type `Balance`; figure out how to find that type
            nom::number::complete::le_u128,
        )),
        |(weight, class, partial_fee)| methods::RuntimeDispatchInfo {
            weight,
            class,
            partial_fee,
        },
    )(value)
}
