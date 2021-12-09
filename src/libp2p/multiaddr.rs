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

    /// Pops the last protocol from the list.
    // TODO: what if list becomes empty? is that legal? what if already empty?
    pub fn pop(&mut self) {
        let remain = {
            let mut iter = nom::combinator::iterator(
                &self.bytes[..],
                nom::combinator::recognize(protocol::<nom::error::Error<&'_ [u8]>>),
            );

            let bytes_prefix = iter.last().unwrap().len();
            self.bytes.len() - bytes_prefix
        };

        self.bytes.truncate(remain);
    }
}

impl AsRef<[u8]> for Multiaddr {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
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
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut bytes = Vec::with_capacity(input.len());
        let mut parts = input.split('/').peekable();

        if parts.next() != Some("") {
            return Err(ParseError::InvalidMultiaddr);
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

impl<'a> FromIterator<ProtocolRef<'a>> for Multiaddr {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ProtocolRef<'a>>,
    {
        let mut bytes = Vec::new();
        for protocol in iter {
            for slice in protocol.as_bytes() {
                bytes.extend(slice.as_ref());
            }
        }
        Multiaddr { bytes }
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

#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub struct FromVecError {}

#[derive(Debug, derive_more::Display, Clone)]
pub enum ParseError {
    /// A multiaddress must always start with `/`.
    InvalidMultiaddr,
    UnexpectedEof,
    UnrecognizedProtocol,
    InvalidPort,
    InvalidIp,
    NotBase58,
    InvalidDomainName,
    InvalidMultihash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRef<'a> {
    Dns(DomainNameRef<'a>),
    Dns4(DomainNameRef<'a>),
    Dns6(DomainNameRef<'a>),
    DnsAddr(DomainNameRef<'a>),
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
    /// Attempts to extract a protocol from an iterator of `/`-separated components.
    pub fn from_str_parts(mut iter: impl Iterator<Item = &'a str>) -> Result<Self, ParseError> {
        match iter.next().ok_or(ParseError::UnexpectedEof)? {
            "dns" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::Dns(DomainNameRef::try_from(addr)?))
            }
            "dns4" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::Dns4(DomainNameRef::try_from(addr)?))
            }
            "dns6" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::Dns6(DomainNameRef::try_from(addr)?))
            }
            "dnsaddr" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::DnsAddr(DomainNameRef::try_from(addr)?))
            }
            "ip4" => {
                let string_ip = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let parsed =
                    no_std_net::Ipv4Addr::from_str(string_ip).map_err(|_| ParseError::InvalidIp)?;
                Ok(ProtocolRef::Ip4(parsed.octets()))
            }
            "ip6" => {
                let string_ip = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let parsed =
                    no_std_net::Ipv6Addr::from_str(string_ip).map_err(|_| ParseError::InvalidIp)?;
                Ok(ProtocolRef::Ip6(parsed.octets()))
            }
            "p2p" => {
                let s = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let decoded = bs58::decode(s)
                    .into_vec()
                    .map_err(|_| ParseError::NotBase58)?;
                if let Err(_) = nom::combinator::all_consuming(
                    super::peer_id::multihash::<nom::error::Error<&'_ [u8]>>,
                )(&decoded)
                {
                    return Err(ParseError::InvalidMultihash);
                }
                Ok(ProtocolRef::P2p(Cow::Owned(decoded)))
            }
            "tcp" => {
                let port = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::Tcp(
                    port.parse().map_err(|_| ParseError::InvalidPort)?,
                ))
            }
            "tls" => Ok(ProtocolRef::Tls),
            "udp" => {
                let port = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(ProtocolRef::Udp(
                    port.parse().map_err(|_| ParseError::InvalidPort)?,
                ))
            }
            "ws" => Ok(ProtocolRef::Ws),
            "wss" => Ok(ProtocolRef::Wss),
            _ => Err(ParseError::UnrecognizedProtocol),
        }
    }

    /// Returns an iterator to a list of buffers that, when concatenated together, form the
    /// binary representation of this protocol.
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
            ProtocolRef::Dns(addr) => {
                let mut out = Vec::with_capacity(addr.0.len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.0.len()));
                out.extend_from_slice(addr.0.as_bytes());
                out
            }
            ProtocolRef::Dns4(addr) => {
                let mut out = Vec::with_capacity(addr.0.len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.0.len()));
                out.extend_from_slice(addr.0.as_bytes());
                out
            }
            ProtocolRef::Dns6(addr) => {
                let mut out = Vec::with_capacity(addr.0.len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.0.len()));
                out.extend_from_slice(addr.0.as_bytes());
                out
            }
            ProtocolRef::DnsAddr(addr) => {
                let mut out = Vec::with_capacity(addr.0.len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.0.len()));
                out.extend_from_slice(addr.0.as_bytes());
                out
            }
            ProtocolRef::Ip4(ip) => ip.to_vec(),
            ProtocolRef::Ip6(ip) => ip.to_vec(),
            ProtocolRef::P2p(multihash) => {
                // TODO: what if not a valid multihash? the enum variant can be constructed by the user
                let mut out = Vec::with_capacity(multihash.len() + 4);
                out.extend(crate::util::leb128::encode_usize(multihash.len()));
                out.extend_from_slice(multihash);
                out
            }
            ProtocolRef::Tcp(port) => port.to_be_bytes().to_vec(),
            ProtocolRef::Udp(port) => port.to_be_bytes().to_vec(),
            _ => Vec::new(),
        };

        let mut out = crate::util::leb128::encode_usize(code).collect::<Vec<_>>();
        out.extend(extra);
        iter::once(out.into_iter())
    }
}

impl<'a> fmt::Display for ProtocolRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Note that since a `DomainNameRef` always contains a valid domain name, it is
            // guaranteed that `addr` never contains a `/`.
            ProtocolRef::Dns(addr) => write!(f, "/dns/{}", addr),
            ProtocolRef::Dns4(addr) => write!(f, "/dns4/{}", addr),
            ProtocolRef::Dns6(addr) => write!(f, "/dns6/{}", addr),
            ProtocolRef::DnsAddr(addr) => write!(f, "/dnsaddr/{}", addr),
            ProtocolRef::Ip4(ip) => fmt::Display::fmt(&no_std_net::Ipv4Addr::from(*ip), f),
            ProtocolRef::Ip6(ip) => fmt::Display::fmt(&no_std_net::Ipv6Addr::from(*ip), f),
            ProtocolRef::P2p(multihash) => {
                // Base58 encoding doesn't have `/` in its characters set.
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

/// Domain name. Guarantees that the domain name is valid.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainNameRef<'a>(&'a str);

impl<'a> TryFrom<&'a str> for DomainNameRef<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        if addr::parse_dns_name(input).is_err() {
            return Err(ParseError::InvalidDomainName);
        }

        Ok(DomainNameRef(input))
    }
}

impl<'a> fmt::Debug for DomainNameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<'a> fmt::Display for DomainNameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Parses a single protocol from its bytes.
fn protocol<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], ProtocolRef<'a>, E> {
    nom::combinator::flat_map(crate::util::leb128::nom_leb128_usize, |protocol_code| {
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
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    |s| {
                        str::from_utf8(s)
                            .ok()
                            .and_then(|s| DomainNameRef::try_from(s).ok())
                    },
                ),
                ProtocolRef::Dns,
            )(bytes),
            54 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    |s| {
                        str::from_utf8(s)
                            .ok()
                            .and_then(|s| DomainNameRef::try_from(s).ok())
                    },
                ),
                ProtocolRef::Dns4,
            )(bytes),
            55 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    |s| {
                        str::from_utf8(s)
                            .ok()
                            .and_then(|s| DomainNameRef::try_from(s).ok())
                    },
                ),
                ProtocolRef::Dns6,
            )(bytes),
            56 => nom::combinator::map(
                nom::combinator::map_opt(
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    |s| {
                        str::from_utf8(s)
                            .ok()
                            .and_then(|s| DomainNameRef::try_from(s).ok())
                    },
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
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
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
