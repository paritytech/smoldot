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

// TODO: needs documentation

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt, iter,
    str::{self, FromStr},
};

use super::multihash;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Multiaddr {
    bytes: Vec<u8>,
}

impl Multiaddr {
    /// Creates a new empty multiaddr.
    pub fn new() -> Self {
        Multiaddr { bytes: Vec::new() }
    }

    /// Pushes a protocol at the end of this multiaddr.
    pub fn push(&mut self, protocol: ProtocolRef) {
        for slice in protocol.as_bytes() {
            self.bytes.extend(slice.as_ref());
        }
    }

    /// Shrinks the memory used by the underlying container to its size.
    pub fn shrink_to_fit(&mut self) {
        self.bytes.shrink_to_fit();
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
    ///
    /// # Panic
    ///
    /// Panics if the multiaddr is empty.
    ///
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
        if nom::combinator::all_consuming(nom::multi::fold_many0(
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
        fmt::Display::fmt(&self, f)
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
    InvalidMultihash(multihash::FromBytesError),
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
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
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
                if let Err(err) = multihash::MultihashRef::from_bytes(&decoded) {
                    return Err(ParseError::InvalidMultihash(err));
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
            ProtocolRef::Dns(addr)
            | ProtocolRef::Dns4(addr)
            | ProtocolRef::Dns6(addr)
            | ProtocolRef::DnsAddr(addr) => {
                let mut out = Vec::with_capacity(addr.as_ref().len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.as_ref().len()));
                out.extend_from_slice(addr.as_ref());
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
            ProtocolRef::Tcp(port) | ProtocolRef::Udp(port) => port.to_be_bytes().to_vec(),
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
            ProtocolRef::Ip4(ip) => write!(f, "/ip4/{}", no_std_net::Ipv4Addr::from(*ip)),
            ProtocolRef::Ip6(ip) => write!(f, "/ip6/{}", no_std_net::Ipv6Addr::from(*ip)),
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

/// Domain name. Guarantees that the domain name has a valid syntax.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainNameRef<'a>(&'a str);

impl<'a> TryFrom<&'a str> for DomainNameRef<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        // Checks whether the input is valid domain name.
        // See https://datatracker.ietf.org/doc/html/rfc2181#section-11

        // An earlier version of this code used the `addr` Rust library, but it resulted in an
        // unnecessarily large binary size overhead (~1.1 MiB!), so the check is now implemented
        // manually instead.

        if input.as_bytes().len() > 255 {
            return Err(ParseError::InvalidDomainName);
        }

        if !input.is_empty() && input != "." {
            // The checks within this for loop would fail if `input` is empty or equal to ".",
            // even though "" and "." are valid domain names.
            for label in input.split_terminator('.') {
                if label.is_empty() || label.as_bytes().len() > 63 {
                    return Err(ParseError::InvalidDomainName);
                }
            }
        }

        // In addition to the standard, we also forbid any domain name containing a `/` byte,
        // because it would mess up with the multiaddress format.
        if input.chars().any(|c| c == '/') || input.as_bytes().iter().any(|b| *b == b'/') {
            return Err(ParseError::InvalidDomainName);
        }

        // Note that success here does in no way guarantee that this domain name is registrable,
        // only that its syntax is valid.

        Ok(DomainNameRef(input))
    }
}

impl<'a> AsRef<[u8]> for DomainNameRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
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
            6 => nom::combinator::map(nom::number::complete::be_u16, ProtocolRef::Tcp)(bytes),
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
            273 => nom::combinator::map(nom::number::complete::be_u16, ProtocolRef::Udp)(bytes),
            421 => nom::combinator::map(
                nom::combinator::verify(
                    nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                    |s| multihash::MultihashRef::from_bytes(s).is_ok(),
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

#[cfg(test)]
mod tests {
    use super::Multiaddr;

    #[test]
    fn basic() {
        fn check_valid(addr: &str) {
            let parsed = addr.parse::<Multiaddr>().unwrap();
            assert_eq!(parsed.to_string(), addr, "{}", addr);
            assert_eq!(
                Multiaddr::try_from(parsed.to_vec()).unwrap(),
                parsed,
                "{}",
                addr
            );
        }

        fn check_invalid(addr: &str) {
            assert!(addr.parse::<Multiaddr>().is_err(), "{}", addr);
        }

        check_valid("");
        check_valid("/ip4/1.2.3.4/tcp/30333");
        check_valid(
            "/ip4/127.0.0.1/tcp/30333/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        );
        check_valid("/ip6/::/udp/30333");
        check_valid("/ip6/::1/udp/30333/tls");
        check_valid("/ip6/::1/udp/30333/tls/ws");
        check_valid("/tcp/65535/udp/65535/ws/tls/wss");
        check_valid("/dns/0.0.0.0");
        check_valid("/dns4/example.com./tcp/55");
        check_valid("/dns6//tcp/55");
        check_valid("/dnsaddr/./tcp/55");

        check_invalid("/");
        check_invalid("ip4/1.2.3.4");
        check_invalid("/nonexistingprotocol");
        check_invalid("/ip4/1.1.1");
        check_invalid("/ip6/:::");
        check_invalid("/ws/1.2.3.4");
        check_invalid("/tcp/65536");
        check_invalid("/p2p/blablabla");
    }
}
