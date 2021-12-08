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

// TODO: needs documentation

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt, iter,
    str::{self, FromStr},
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Multiaddr {
    bytes: Vec<u8>,
}

impl Multiaddr {
    /// Shrinks the memory used by the underlying container to its size.
    pub fn shrink_to_fit(&mut self) {
        self.bytes.shrink_to_fit()
    }

    /// Returns the serialized version of this multiaddr.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Returns the list of components of the multiaddress.
    pub fn iter(&'_ self) -> impl Iterator<Item = ProtocolRef<'_>> + '_ {
        let mut iter =
            nom::combinator::iterator(&self.bytes[..], protocol::<nom::error::Error<&'_ [u8]>>);
        iter::from_fn(move || (&mut iter).next())
    }
}

impl<'a> From<ProtocolRef<'a>> for Multiaddr {
    fn from(proto: ProtocolRef<'a>) -> Multiaddr {
        let bytes = proto.as_bytes().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        Multiaddr { bytes }
    }
}

impl FromStr for Multiaddr {
    type Err = (); // TODO: better than ()

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut bytes = Vec::with_capacity(input.len());
        let mut parts = input.split('/').peekable();

        if parts.next() != Some("") {
            return Err(());
        }

        while parts.peek().is_some() {
            let protocol = ProtocolRef::from_str_parts(&mut parts)?;
            for slice in protocol.as_bytes() {
                bytes.extend_from_slice(slice.as_ref());
            }
        }

        Ok(Multiaddr { bytes })
    }
}

impl TryFrom<Vec<u8>> for Multiaddr {
    type Error = FromVecError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Check whether this is indeed a valid list of protocols.
        if nom::combinator::all_consuming(nom::multi::fold_many1(
            protocol::<nom::error::Error<&[u8]>>,
            || (),
            |(), _| (),
        ))(&bytes)
        .is_err()
        {
            return Err(FromVecError {});
        }

        Ok(Multiaddr { bytes })
    }
}

#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub struct FromVecError {}

impl fmt::Debug for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(&mut nom::combinator::iterator(
                &self.bytes[..],
                protocol::<nom::error::Error<&[u8]>>,
            ))
            .finish()
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for protocol in self.iter() {
            fmt::Display::fmt(&protocol, f)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRef<'a> {
    Dns(&'a str),
    Dns4(&'a str),
    Dns6(&'a str),
    DnsAddr(&'a str),
    Ip4([u8; 4]),
    Ip6([u8; 16]),
    P2p(Cow<'a, [u8]>), // TODO: a bit hacky
    Quic,
    Tcp(u16),
    Tls,
    Udp(u16),
    Ws,
    Wss,
}

impl<'a> ProtocolRef<'a> {
    pub fn from_str_parts(mut iter: impl Iterator<Item = &'a str>) -> Result<Self, ()> {
        match iter.next().ok_or(())? {
            "dns" => {
                let addr = iter.next().ok_or(())?;
                Ok(ProtocolRef::Dns(addr))
            }
            "dns4" => {
                let addr = iter.next().ok_or(())?;
                Ok(ProtocolRef::Dns4(addr))
            }
            "dns6" => {
                let addr = iter.next().ok_or(())?;
                Ok(ProtocolRef::Dns6(addr))
            }
            "dnsaddr" => {
                let addr = iter.next().ok_or(())?;
                Ok(ProtocolRef::DnsAddr(addr))
            }
            "ip4" => {
                let string_ip = iter.next().ok_or(())?;
                let parsed = no_std_net::Ipv4Addr::from_str(string_ip).map_err(|_| ())?;
                Ok(ProtocolRef::Ip4(parsed.octets()))
            }
            "ip6" => {
                let string_ip = iter.next().ok_or(())?;
                let parsed = no_std_net::Ipv6Addr::from_str(string_ip).map_err(|_| ())?;
                Ok(ProtocolRef::Ip6(parsed.octets()))
            }
            "p2p" => {
                let s = iter.next().ok_or(())?;
                let decoded = bs58::decode(s).into_vec().map_err(|_| ())?;
                // TODO: must check if valid multihash /!\
                Ok(ProtocolRef::P2p(Cow::Owned(decoded)))
            }
            "tcp" => {
                let port = iter.next().ok_or(())?;
                Ok(ProtocolRef::Tcp(port.parse().map_err(|_| ())?))
            }
            "tls" => Ok(ProtocolRef::Tls),
            "udp" => {
                let port = iter.next().ok_or(())?;
                Ok(ProtocolRef::Udp(port.parse().map_err(|_| ())?))
            }
            "ws" => Ok(ProtocolRef::Ws),
            "wss" => Ok(ProtocolRef::Wss),
            _ => Err(()),
        }
    }

    pub fn as_bytes(&self) -> impl Iterator<Item = impl AsRef<[u8]>> {
        let code = match self {
            ProtocolRef::Dns(_) => 53,
            ProtocolRef::Dns4(_) => 54,
            ProtocolRef::Dns6(_) => 55,
            ProtocolRef::DnsAddr(_) => 56,
            ProtocolRef::Ip4(_) => 4,
            ProtocolRef::Ip6(_) => 41,
            ProtocolRef::P2p(_) => 421,
            ProtocolRef::Quic => 460,
            ProtocolRef::Tcp(_) => 6,
            ProtocolRef::Tls => 448,
            ProtocolRef::Udp(_) => 273,
            ProtocolRef::Ws => 477,
            ProtocolRef::Wss => 478,
        };

        // TODO: optimize by not allocating a Vec
        let extra = match self {
            ProtocolRef::Dns(addr) => addr.as_bytes().to_vec(),
            ProtocolRef::Dns4(addr) => addr.as_bytes().to_vec(),
            ProtocolRef::Dns6(addr) => addr.as_bytes().to_vec(),
            ProtocolRef::DnsAddr(addr) => addr.as_bytes().to_vec(),
            ProtocolRef::Ip4(ip) => ip.to_vec(),
            ProtocolRef::Ip6(ip) => ip.to_vec(),
            ProtocolRef::P2p(multihash) => multihash.to_vec(),
            ProtocolRef::Tcp(port) => port.to_be_bytes().to_vec(),
            ProtocolRef::Udp(port) => port.to_be_bytes().to_vec(),
            _ => Vec::new(),
        };

        let code = crate::util::encode_scale_compact_usize(code);
        [either::Left(code), either::Right(extra)].into_iter()
    }
}

impl<'a> fmt::Display for ProtocolRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: what if DNS address contains a `/`?
        match self {
            ProtocolRef::Dns(addr) => write!(f, "/dns/{}", addr),
            ProtocolRef::Dns4(addr) => write!(f, "/dns4/{}", addr),
            ProtocolRef::Dns6(addr) => write!(f, "/dns6/{}", addr),
            ProtocolRef::DnsAddr(addr) => write!(f, "/dnsaddr/{}", addr),
            ProtocolRef::Ip4(ip) => fmt::Display::fmt(&no_std_net::Ipv4Addr::from(*ip), f),
            ProtocolRef::Ip6(ip) => fmt::Display::fmt(&no_std_net::Ipv6Addr::from(*ip), f),
            ProtocolRef::P2p(multihash) => {
                write!(f, "/p2p/{}", bs58::encode(multihash).into_string())
            }
            ProtocolRef::Quic => write!(f, "/quic"),
            ProtocolRef::Tcp(port) => write!(f, "/tcp/{}", port),
            ProtocolRef::Tls => write!(f, "/tls"),
            ProtocolRef::Udp(port) => write!(f, "/udp/{}", port),
            ProtocolRef::Ws => write!(f, "/ws"),
            ProtocolRef::Wss => write!(f, "/wss"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultihashRef<'a>(&'a [u8]);

/// Parses a single protocol from its bytes.
fn protocol<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], ProtocolRef<'a>, E> {
    nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |protocol_code| {
        move |bytes: &'a [u8]| match protocol_code {
            4 => nom::combinator::map(nom::bytes::complete::take(4_u32), |ip: &'a [u8]| {
                ProtocolRef::Ip4(ip.try_into().unwrap())
            })(bytes),
            6 => {
                nom::combinator::map(nom::number::complete::be_u16, |port| ProtocolRef::Tcp(port))(
                    bytes,
                )
            }
            41 => nom::combinator::map(nom::bytes::complete::take(16_u32), |ip: &'a [u8]| {
                ProtocolRef::Ip6(ip.try_into().unwrap())
            })(bytes),
            53 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    |s| str::from_utf8(s).ok(),
                ),
                ProtocolRef::Dns,
            )(bytes),
            54 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    |s| str::from_utf8(s).ok(),
                ),
                ProtocolRef::Dns4,
            )(bytes),
            55 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    |s| str::from_utf8(s).ok(),
                ),
                ProtocolRef::Dns6,
            )(bytes),
            56 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    |s| str::from_utf8(s).ok(),
                ),
                ProtocolRef::DnsAddr,
            )(bytes),
            273 => {
                nom::combinator::map(nom::number::complete::be_u16, |port| ProtocolRef::Udp(port))(
                    bytes,
                )
            }
            421 => nom::combinator::map(
                nom::combinator::map_parser(
                    nom::multi::length_data(crate::util::nom_scale_compact_usize),
                    nom::combinator::recognize(nom::combinator::all_consuming(
                        super::peer_id::multihash,
                    )),
                ),
                |b| ProtocolRef::P2p(Cow::Borrowed(b)),
            )(bytes),
            448 => Ok((bytes, ProtocolRef::Tls)),
            460 => Ok((bytes, ProtocolRef::Quic)),
            477 => Ok((bytes, ProtocolRef::Ws)),
            478 => Ok((bytes, ProtocolRef::Wss)),
            _ => Err(nom::Err::Error(nom::error::make_error(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    })(bytes)
}
