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
use base64::Engine as _;
use core::{
    fmt, iter, net,
    str::{self, FromStr},
};

pub use super::multihash::{FromBytesError as MultihashFromBytesError, Multihash};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Multiaddr<T = Vec<u8>> {
    bytes: T,
}

impl Multiaddr<Vec<u8>> {
    /// Creates a new empty `Multiaddr`.
    pub fn empty() -> Self {
        Multiaddr { bytes: Vec::new() }
    }

    /// Pushes a protocol at the end of this `Multiaddr`.
    pub fn push(&mut self, protocol: Protocol) {
        for slice in protocol.as_bytes() {
            self.bytes.extend(slice.as_ref());
        }
    }

    /// Shrinks the memory used by the underlying container to its size.
    pub fn shrink_to_fit(&mut self) {
        self.bytes.shrink_to_fit();
    }

    /// Pops the last protocol from the list.
    ///
    /// # Panic
    ///
    /// Panics if the `Multiaddr` is empty.
    ///
    pub fn pop(&mut self) {
        let remain = {
            let iter = nom::combinator::iterator(
                &self.bytes[..],
                nom::combinator::recognize(protocol::<&[u8], nom::error::Error<&[u8]>>),
            );

            let bytes_prefix = iter.last().unwrap().len();
            self.bytes.len() - bytes_prefix
        };

        self.bytes.truncate(remain);
    }
}

impl<T> Multiaddr<T> {
    /// Returns the serialized version of this `Multiaddr`.
    pub fn into_bytes(self) -> T {
        self.bytes
    }
}

impl<T: AsRef<[u8]>> Multiaddr<T> {
    /// Checks whether the given bytes have the proper format, and if so wraps them
    /// around a [`Multiaddr`].
    pub fn from_bytes(bytes: T) -> Result<Self, (FromBytesError, T)> {
        // Check whether this is indeed a valid list of protocols.
        if nom::Parser::parse(
            &mut nom::combinator::all_consuming(nom::multi::fold_many0(
                nom::combinator::complete(protocol::<&[u8], nom::error::Error<&[u8]>>),
                || (),
                |(), _| (),
            )),
            bytes.as_ref(),
        )
        .is_err()
        {
            return Err((FromBytesError, bytes));
        }

        Ok(Multiaddr { bytes })
    }

    /// Returns the list of components of the multiaddress.
    pub fn iter(&self) -> impl Iterator<Item = Protocol<&[u8]>> {
        let mut iter =
            nom::combinator::iterator(self.bytes.as_ref(), protocol::<_, nom::error::Error<&[u8]>>);
        iter::from_fn(move || (&mut iter).next())
    }
}

impl<T> AsRef<T> for Multiaddr<T> {
    fn as_ref(&self) -> &T {
        &self.bytes
    }
}

impl<T: AsRef<[u8]>> From<Protocol<T>> for Multiaddr<Vec<u8>> {
    fn from(proto: Protocol<T>) -> Multiaddr<Vec<u8>> {
        let bytes = proto.as_bytes().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        });

        Multiaddr { bytes }
    }
}

impl FromStr for Multiaddr<Vec<u8>> {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut bytes = Vec::with_capacity(input.len());
        let mut parts = input.split('/').peekable();

        if parts.next() != Some("") {
            return Err(ParseError::InvalidMultiaddr);
        }

        while parts.peek().is_some() {
            let protocol = Protocol::from_str_parts(&mut parts)?;
            for slice in protocol.as_bytes() {
                bytes.extend_from_slice(slice.as_ref());
            }
        }

        Ok(Multiaddr { bytes })
    }
}

impl<T: AsRef<[u8]>> FromIterator<Protocol<T>> for Multiaddr<Vec<u8>> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Protocol<T>>,
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

impl<T: AsRef<[u8]>> fmt::Debug for Multiaddr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Multiaddr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for protocol in self.iter() {
            fmt::Display::fmt(&protocol, f)?;
        }

        Ok(())
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
#[display("Unable to parse multiaddress")]
pub struct FromBytesError;

// TODO: more doc and properly derive Display
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum ParseError {
    /// A multiaddress must always start with `/`.
    InvalidMultiaddr,
    UnexpectedEof,
    UnrecognizedProtocol,
    InvalidPort,
    InvalidIp,
    NotBase58,
    InvalidDomainName,
    InvalidMultihash(MultihashFromBytesError),
    InvalidMemoryPayload,
    InvalidMultibase,
    InvalidBase64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Protocol<T = Vec<u8>> {
    Dns(DomainName<T>),
    Dns4(DomainName<T>),
    Dns6(DomainName<T>),
    DnsAddr(DomainName<T>),
    Ip4([u8; 4]),
    Ip6([u8; 16]),
    P2p(Multihash<T>), // TODO: put directly a PeerId? unclear
    Quic,
    QuicV1,
    WebTransport,
    Tcp(u16),
    Tls,
    Udp(u16),
    Ws,
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    Wss,
    // TODO: unclear what the payload is; see https://github.com/multiformats/multiaddr/issues/127
    Memory(u64),
    WebRtcDirect,
    /// Contains the multihash of the TLS certificate.
    Certhash(Multihash<T>),
}

impl<'a> Protocol<Cow<'a, [u8]>> {
    /// Attempts to extract a protocol from an iterator of `/`-separated components.
    pub fn from_str_parts(mut iter: impl Iterator<Item = &'a str>) -> Result<Self, ParseError> {
        match iter.next().ok_or(ParseError::UnexpectedEof)? {
            "dns" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Dns(DomainName::from_bytes(Cow::Borrowed(
                    addr.as_bytes(),
                ))?))
            }
            "dns4" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Dns4(DomainName::from_bytes(Cow::Borrowed(
                    addr.as_bytes(),
                ))?))
            }
            "dns6" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Dns6(DomainName::from_bytes(Cow::Borrowed(
                    addr.as_bytes(),
                ))?))
            }
            "dnsaddr" => {
                let addr = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::DnsAddr(DomainName::from_bytes(Cow::Borrowed(
                    addr.as_bytes(),
                ))?))
            }
            "ip4" => {
                let string_ip = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let parsed =
                    net::Ipv4Addr::from_str(string_ip).map_err(|_| ParseError::InvalidIp)?;
                Ok(Protocol::Ip4(parsed.octets()))
            }
            "ip6" => {
                let string_ip = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let parsed =
                    net::Ipv6Addr::from_str(string_ip).map_err(|_| ParseError::InvalidIp)?;
                Ok(Protocol::Ip6(parsed.octets()))
            }
            "p2p" => {
                let s = iter.next().ok_or(ParseError::UnexpectedEof)?;
                let decoded = bs58::decode(s)
                    .into_vec()
                    .map_err(|_| ParseError::NotBase58)?;
                Ok(Protocol::P2p(
                    Multihash::from_bytes(Cow::Owned(decoded))
                        .map_err(|(err, _)| ParseError::InvalidMultihash(err))?,
                ))
            }
            "tcp" => {
                let port = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Tcp(
                    port.parse().map_err(|_| ParseError::InvalidPort)?,
                ))
            }
            "tls" => Ok(Protocol::Tls),
            "udp" => {
                let port = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Udp(
                    port.parse().map_err(|_| ParseError::InvalidPort)?,
                ))
            }
            "ws" => Ok(Protocol::Ws),
            "wss" => Ok(Protocol::Wss),
            "memory" => {
                let payload = iter.next().ok_or(ParseError::UnexpectedEof)?;
                Ok(Protocol::Memory(
                    payload
                        .parse()
                        .map_err(|_| ParseError::InvalidMemoryPayload)?,
                ))
            }
            "webrtc-direct" => Ok(Protocol::WebRtcDirect),
            "quic-v1" => Ok(Protocol::QuicV1),
            "webtransport" => Ok(Protocol::WebTransport),
            "certhash" => {
                let s = iter.next().ok_or(ParseError::UnexpectedEof)?;
                // See <https://github.com/multiformats/multibase#multibase-table>
                let base64_flavor = match s.as_bytes().first() {
                    Some(b'm') => base64::engine::general_purpose::STANDARD_NO_PAD,
                    Some(b'M') => base64::engine::general_purpose::STANDARD,
                    Some(b'u') => base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    Some(b'U') => base64::engine::general_purpose::URL_SAFE,
                    _ => return Err(ParseError::InvalidMultibase),
                };
                let decoded = base64_flavor
                    .decode(&s[1..])
                    .map_err(|_| ParseError::InvalidBase64)?;
                Ok(Protocol::Certhash(
                    Multihash::from_bytes(Cow::Owned(decoded))
                        .map_err(|(err, _)| ParseError::InvalidMultihash(err))?,
                ))
            }
            _ => Err(ParseError::UnrecognizedProtocol),
        }
    }
}

impl<T: AsRef<[u8]>> Protocol<T> {
    /// Returns an iterator to a list of buffers that, when concatenated together, form the
    /// binary representation of this protocol.
    pub fn as_bytes(&self) -> impl Iterator<Item = impl AsRef<[u8]>> {
        let code = match self {
            Protocol::Dns(_) => 53,
            Protocol::Dns4(_) => 54,
            Protocol::Dns6(_) => 55,
            Protocol::DnsAddr(_) => 56,
            Protocol::Ip4(_) => 4,
            Protocol::Ip6(_) => 41,
            Protocol::P2p(_) => 421,
            Protocol::Quic => 460,
            Protocol::QuicV1 => 461,
            Protocol::WebTransport => 465,
            Protocol::Tcp(_) => 6,
            Protocol::Tls => 448,
            Protocol::Udp(_) => 273,
            Protocol::Ws => 477,
            Protocol::Wss => 478,
            Protocol::Memory(_) => 777,
            Protocol::WebRtcDirect => 280,
            Protocol::Certhash(_) => 466,
        };

        // TODO: optimize by not allocating a Vec
        let extra = match self {
            Protocol::Dns(addr)
            | Protocol::Dns4(addr)
            | Protocol::Dns6(addr)
            | Protocol::DnsAddr(addr) => {
                let addr = addr.as_ref().as_ref();
                let mut out = Vec::with_capacity(addr.len() + 4);
                out.extend(crate::util::leb128::encode_usize(addr.len()));
                out.extend_from_slice(addr);
                out
            }
            Protocol::Ip4(ip) => ip.to_vec(),
            Protocol::Ip6(ip) => ip.to_vec(),
            Protocol::P2p(multihash) => {
                let multihash = multihash.as_ref().as_ref();
                // TODO: what if not a valid multihash? the enum variant can be constructed by the user
                let mut out = Vec::with_capacity(multihash.len() + 4);
                out.extend(crate::util::leb128::encode_usize(multihash.len()));
                out.extend_from_slice(multihash);
                out
            }
            Protocol::Tcp(port) | Protocol::Udp(port) => port.to_be_bytes().to_vec(),
            Protocol::Memory(payload) => payload.to_be_bytes().to_vec(),
            Protocol::Certhash(multihash) => {
                let multihash = multihash.as_ref().as_ref();
                // TODO: what if not a valid multihash? the enum variant can be constructed by the user
                let mut out = Vec::with_capacity(multihash.len() + 4);
                out.extend(crate::util::leb128::encode_usize(multihash.len()));
                out.extend_from_slice(multihash);
                out
            }
            _ => Vec::new(),
        };

        // Combine `code` and `extra`.
        crate::util::leb128::encode_usize(code)
            .map(|b| either::Left([b]))
            .chain(iter::once(either::Right(extra)))
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for Protocol<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Protocol<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Note that since a `DomainName` always contains a valid domain name, it is
            // guaranteed that `addr` never contains a `/`.
            Protocol::Dns(addr) => write!(f, "/dns/{addr}"),
            Protocol::Dns4(addr) => write!(f, "/dns4/{addr}"),
            Protocol::Dns6(addr) => write!(f, "/dns6/{addr}"),
            Protocol::DnsAddr(addr) => write!(f, "/dnsaddr/{addr}"),
            Protocol::Ip4(ip) => write!(f, "/ip4/{}", net::Ipv4Addr::from(*ip)),
            Protocol::Ip6(ip) => write!(f, "/ip6/{}", net::Ipv6Addr::from(*ip)),
            Protocol::P2p(multihash) => {
                // Base58 encoding doesn't have `/` in its characters set.
                write!(f, "/p2p/{}", bs58::encode(multihash.as_ref()).into_string())
            }
            Protocol::Quic => write!(f, "/quic"),
            Protocol::QuicV1 => write!(f, "/quic-v1"),
            Protocol::WebTransport => write!(f, "/webtransport"),
            Protocol::Tcp(port) => write!(f, "/tcp/{port}"),
            Protocol::Tls => write!(f, "/tls"),
            Protocol::Udp(port) => write!(f, "/udp/{port}"),
            Protocol::Ws => write!(f, "/ws"),
            Protocol::Wss => write!(f, "/wss"),
            Protocol::Memory(payload) => write!(f, "/memory/{payload}"),
            Protocol::WebRtcDirect => write!(f, "/webrtc-direct"),
            Protocol::Certhash(multihash) => {
                write!(
                    f,
                    "/certhash/u{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(multihash.as_ref())
                )
            }
        }
    }
}

/// Domain name. Guarantees that the domain name has a valid syntax.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName<T = Vec<u8>>(T);

impl<T> DomainName<T> {
    /// Returns the underlying bytes of the domain name.
    pub fn into_bytes(self) -> T {
        self.0
    }

    /// Try to parse the given string as a domain name.
    pub fn from_bytes(bytes: T) -> Result<DomainName<T>, ParseError>
    where
        T: AsRef<[u8]>,
    {
        // Checks whether the input is valid domain name.
        // See https://datatracker.ietf.org/doc/html/rfc2181#section-11

        // An earlier version of this code used the `addr` Rust library, but it resulted in an
        // unnecessarily large binary size overhead (~1.1 MiB!), so the check is now implemented
        // manually instead.

        let as_str = str::from_utf8(bytes.as_ref()).map_err(|_| ParseError::InvalidDomainName)?;

        if as_str.len() > 255 {
            return Err(ParseError::InvalidDomainName);
        }

        if !as_str.is_empty() && as_str != "." {
            // The checks within this for loop would fail if `input` is empty or equal to ".",
            // even though "" and "." are valid domain names.
            for label in as_str.split_terminator('.') {
                if label.is_empty() || label.as_bytes().len() > 63 {
                    return Err(ParseError::InvalidDomainName);
                }
            }
        }

        // In addition to the standard, we also forbid any domain name containing a `/` byte,
        // because it would mess up with the multiaddress format.
        if as_str.chars().any(|c| c == '/') || as_str.as_bytes().iter().any(|b| *b == b'/') {
            return Err(ParseError::InvalidDomainName);
        }

        // Note that success here does in no way guarantee that this domain name is registrable,
        // only that its syntax is valid.

        Ok(DomainName(bytes))
    }
}

impl<T> AsRef<T> for DomainName<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for DomainName<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let as_str = str::from_utf8(self.0.as_ref()).unwrap();
        fmt::Debug::fmt(as_str, f)
    }
}

impl<T: AsRef<[u8]>> fmt::Display for DomainName<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let as_str = str::from_utf8(self.0.as_ref()).unwrap();
        fmt::Display::fmt(as_str, f)
    }
}

/// Parses a single protocol from its bytes.
fn protocol<'a, T: From<&'a [u8]> + AsRef<[u8]>, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], Protocol<T>, E> {
    nom::Parser::parse(
        &mut nom::combinator::flat_map(crate::util::leb128::nom_leb128_usize, |protocol_code| {
            move |bytes: &'a [u8]| match protocol_code {
                4 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::bytes::streaming::take(4_u32),
                        |ip: &'a [u8]| Protocol::Ip4(ip.try_into().unwrap()),
                    ),
                    bytes,
                ),
                6 => nom::Parser::parse(
                    &mut nom::combinator::map(nom::number::streaming::be_u16, Protocol::Tcp),
                    bytes,
                ),
                41 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::bytes::streaming::take(16_u32),
                        |ip: &'a [u8]| Protocol::Ip6(ip.try_into().unwrap()),
                    ),
                    bytes,
                ),
                53 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| DomainName::from_bytes(T::from(s)).ok(),
                        ),
                        Protocol::Dns,
                    ),
                    bytes,
                ),
                54 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| DomainName::from_bytes(T::from(s)).ok(),
                        ),
                        Protocol::Dns4,
                    ),
                    bytes,
                ),
                55 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| DomainName::from_bytes(T::from(s)).ok(),
                        ),
                        Protocol::Dns6,
                    ),
                    bytes,
                ),
                56 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| DomainName::from_bytes(T::from(s)).ok(),
                        ),
                        Protocol::DnsAddr,
                    ),
                    bytes,
                ),
                273 => nom::Parser::parse(
                    &mut nom::combinator::map(nom::number::streaming::be_u16, Protocol::Udp),
                    bytes,
                ),
                421 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| Multihash::from_bytes(From::from(s)).ok(),
                        ),
                        Protocol::P2p,
                    ),
                    bytes,
                ),
                448 => Ok((bytes, Protocol::Tls)),
                460 => Ok((bytes, Protocol::Quic)),
                461 => Ok((bytes, Protocol::QuicV1)),
                465 => Ok((bytes, Protocol::WebTransport)),
                477 => Ok((bytes, Protocol::Ws)),
                478 => Ok((bytes, Protocol::Wss)),
                // TODO: unclear what the /memory payload is, see https://github.com/multiformats/multiaddr/issues/127
                777 => nom::Parser::parse(
                    &mut nom::combinator::map(nom::number::streaming::be_u64, Protocol::Memory),
                    bytes,
                ),
                280 => Ok((bytes, Protocol::WebRtcDirect)),
                466 => nom::Parser::parse(
                    &mut nom::combinator::map(
                        nom::combinator::map_opt(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            |s| Multihash::from_bytes(From::from(s)).ok(),
                        ),
                        Protocol::Certhash,
                    ),
                    bytes,
                ),
                _ => Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Tag,
                ))),
            }
        }),
        bytes,
    )
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
                Multiaddr::from_bytes(parsed.as_ref().to_vec()).unwrap(),
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
        check_valid("/memory/1234567890");
        check_valid("/webrtc-direct");
        check_valid("/ip4/127.0.0.1/udp/40000/quic-v1/webtransport");
        check_valid("/ip6/::1/udp/40000/quic-v1/webtransport");
        // TODO: example valid /certhash

        check_invalid("/");
        check_invalid("ip4/1.2.3.4");
        check_invalid("/nonexistingprotocol");
        check_invalid("/ip4/1.1.1");
        check_invalid("/ip6/:::");
        check_invalid("/ws/1.2.3.4");
        check_invalid("/tcp/65536");
        check_invalid("/p2p/blablabla");
        check_invalid("/webrtc-direct/2");
        check_invalid("/webtransport/2");
        check_invalid("/certhash");
        check_invalid("/certhash/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
    }

    #[test]
    fn webtransport_codes() {
        let addr: Multiaddr = "/quic-v1/webtransport".parse().unwrap();
        assert_eq!(addr.as_ref(), &[0xcd, 0x03, 0xd1, 0x03]);
        assert_eq!(Multiaddr::from_bytes(addr.as_ref().to_vec()).unwrap(), addr);
        assert!(Multiaddr::from_bytes(vec![0xcd]).is_err());
        assert!(Multiaddr::from_bytes(vec![0xcd, 3, 0xd1]).is_err());
    }
}
