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

//! Decodes yamux headers.
//!
//! See <https://github.com/hashicorp/yamux/blob/master/spec.md>

use core::num::NonZeroU32;

/// A Yamux header in its decoded form.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DecodedYamuxHeader {
    Data {
        /// Value of the SYN flag.
        syn: bool,
        /// Value of the ACK flag.
        ack: bool,
        /// Value of the FIN flag.
        fin: bool,
        /// Value of the RST flag.
        rst: bool,
        stream_id: NonZeroU32,
        length: u32,
    },
    Window {
        /// Value of the SYN flag.
        syn: bool,
        /// Value of the ACK flag.
        ack: bool,
        /// Value of the FIN flag.
        fin: bool,
        /// Value of the RST flag.
        rst: bool,
        stream_id: NonZeroU32,
        length: u32,
    },
    PingRequest {
        opaque_value: u32,
    },
    PingResponse {
        opaque_value: u32,
    },
    GoAway {
        error_code: GoAwayErrorCode,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GoAwayErrorCode {
    NormalTermination = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
}

/// Decodes a Yamux header.
pub fn decode_yamux_header(bytes: &[u8]) -> Result<DecodedYamuxHeader, YamuxHeaderDecodeError> {
    match nom::combinator::all_consuming(nom::combinator::complete(decode))(bytes) {
        Ok((_, h)) => Ok(h),
        Err(nom::Err::Incomplete(_)) => unreachable!(),
        Err(nom::Err::Failure(err) | nom::Err::Error(err)) => Err(YamuxHeaderDecodeError {
            offset: err.input.as_ptr() as usize - bytes.as_ptr() as usize,
        }),
    }
}

/// Error while decoding a Yamux header.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Error at offset {}", offset)]
pub struct YamuxHeaderDecodeError {
    offset: usize,
}

fn decode<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], DecodedYamuxHeader> {
    nom::sequence::preceded(
        nom::bytes::complete::tag(&[0]),
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::tag(&[0]),
                    flags,
                    nom::combinator::map_opt(nom::number::complete::be_u32, NonZeroU32::new),
                    nom::number::complete::be_u32,
                )),
                |(_, (syn, ack, fin, rst), stream_id, length)| DecodedYamuxHeader::Data {
                    syn,
                    ack,
                    fin,
                    rst,
                    stream_id,
                    length,
                },
            ),
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::tag(&[1]),
                    flags,
                    nom::combinator::map_opt(nom::number::complete::be_u32, NonZeroU32::new),
                    nom::number::complete::be_u32,
                )),
                |(_, (syn, ack, fin, rst), stream_id, length)| DecodedYamuxHeader::Window {
                    syn,
                    ack,
                    fin,
                    rst,
                    stream_id,
                    length,
                },
            ),
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::tag(&[2]),
                    nom::bytes::complete::tag(&[0x0, 0x1]),
                    nom::bytes::complete::tag(&[0, 0, 0, 0]),
                    nom::number::complete::be_u32,
                )),
                |(_, _, _, opaque_value)| DecodedYamuxHeader::PingRequest { opaque_value },
            ),
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::tag(&[2]),
                    nom::bytes::complete::tag(&[0x0, 0x2]),
                    nom::bytes::complete::tag(&[0, 0, 0, 0]),
                    nom::number::complete::be_u32,
                )),
                |(_, _, _, opaque_value)| DecodedYamuxHeader::PingResponse { opaque_value },
            ),
            nom::combinator::map(
                nom::sequence::tuple((
                    nom::bytes::complete::tag(&[3]),
                    nom::bytes::complete::tag(&[0, 0]),
                    nom::bytes::complete::tag(&[0, 0, 0, 0]),
                    nom::branch::alt((
                        nom::combinator::map(nom::bytes::complete::tag(0u32.to_be_bytes()), |_| {
                            GoAwayErrorCode::NormalTermination
                        }),
                        nom::combinator::map(nom::bytes::complete::tag(1u32.to_be_bytes()), |_| {
                            GoAwayErrorCode::ProtocolError
                        }),
                        nom::combinator::map(nom::bytes::complete::tag(2u32.to_be_bytes()), |_| {
                            GoAwayErrorCode::InternalError
                        }),
                    )),
                )),
                |(_, _, _, error_code)| DecodedYamuxHeader::GoAway { error_code },
            ),
        )),
    )(bytes)
}

fn flags<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], (bool, bool, bool, bool)> {
    nom::combinator::map_opt(nom::number::complete::be_u16, |flags| {
        let syn = (flags & 0x1) != 0;
        let ack = (flags & 0x2) != 0;
        let fin = (flags & 0x4) != 0;
        let rst = (flags & 0x8) != 0;
        if (flags & !0b1111) != 0 {
            return None;
        }
        Some((syn, ack, fin, rst))
    })(bytes)
}
