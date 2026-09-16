// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

use alloc::{borrow::Cow, vec::Vec};
use smoldot::libp2p::multiaddr::{Multiaddr, Protocol};

use super::{Address, ConnectionType, MultiStreamAddress};
use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
};

pub enum AddressOrMultiStreamAddress<'a> {
    Address(Address<'a>),
    MultiStreamAddress(MultiStreamAddress<'a>),
}

impl<'a> From<&'a AddressOrMultiStreamAddress<'a>> for ConnectionType {
    fn from(address: &'a AddressOrMultiStreamAddress<'a>) -> ConnectionType {
        match address {
            AddressOrMultiStreamAddress::Address(a) => ConnectionType::from(a),
            AddressOrMultiStreamAddress::MultiStreamAddress(a) => ConnectionType::from(a),
        }
    }
}

/// Parses a [`Multiaddr`] into an [`Address`] or [`MultiStreamAddress`].
pub fn multiaddr_to_address(
    multiaddr: &'_ Multiaddr,
) -> Result<AddressOrMultiStreamAddress<'_>, Error> {
    let mut iter = multiaddr.iter().fuse();

    let proto1 = iter.next().ok_or(Error::UnknownCombination)?;
    let proto2 = iter.next().ok_or(Error::UnknownCombination)?;
    let proto3 = iter.next();
    let proto4 = iter.next();

    if let (Protocol::Udp(port), Some(Protocol::QuicV1), Some(Protocol::WebTransport)) =
        (&proto2, &proto3, &proto4)
    {
        let ip = match proto1 {
            Protocol::Ip4(ip) => IpAddr::V4(Ipv4Addr::from(ip)),
            Protocol::Ip6(ip) => IpAddr::V6(Ipv6Addr::from(ip)),
            _ => return Err(Error::UnknownCombination),
        };
        let mut cert_hashes = Vec::new();
        for protocol in iter {
            let Protocol::Certhash(hash) = protocol else {
                return Err(Error::UnknownCombination);
            };
            if hash.hash_algorithm_code() != 0x12 {
                return Err(Error::NonSha256Certhash);
            }
            cert_hashes.push(
                <[u8; 32]>::try_from(hash.data_ref()).map_err(|_| Error::InvalidMultihashLength)?,
            );
        }
        if cert_hashes.is_empty() {
            return Err(Error::UnknownCombination);
        }
        return Ok(AddressOrMultiStreamAddress::MultiStreamAddress(
            MultiStreamAddress::WebTransport {
                ip,
                port: *port,
                cert_hashes: Cow::Owned(cert_hashes),
            },
        ));
    }

    if iter.next().is_some() {
        return Err(Error::UnknownCombination);
    }

    Ok(match (proto1, proto2, proto3, proto4) {
        (Protocol::Ip4(ip), Protocol::Tcp(port), None, None) => {
            AddressOrMultiStreamAddress::Address(Address::TcpIp {
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            })
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), None, None) => {
            AddressOrMultiStreamAddress::Address(Address::TcpIp {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            })
        }
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            None,
            None,
        ) => AddressOrMultiStreamAddress::Address(Address::TcpDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
        }),
        (Protocol::Ip4(ip), Protocol::Tcp(port), Some(Protocol::Ws), None) => {
            AddressOrMultiStreamAddress::Address(Address::WebSocketIp {
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            })
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Some(Protocol::Ws), None) => {
            AddressOrMultiStreamAddress::Address(Address::WebSocketIp {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            })
        }
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Ws),
            None,
        ) => AddressOrMultiStreamAddress::Address(Address::WebSocketDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
            secure: false,
        }),
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Wss),
            None,
        )
        | (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Tls),
            Some(Protocol::Ws),
        ) => AddressOrMultiStreamAddress::Address(Address::WebSocketDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
            secure: true,
        }),

        (
            Protocol::Ip4(ip),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => {
            if multihash.hash_algorithm_code() != 0x12 {
                return Err(Error::NonSha256Certhash);
            }
            let Ok(remote_certificate_sha256) = <&[u8; 32]>::try_from(multihash.data_ref()) else {
                return Err(Error::InvalidMultihashLength);
            };
            AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
                port,
                remote_certificate_sha256,
            })
        }

        (
            Protocol::Ip6(ip),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => {
            if multihash.hash_algorithm_code() != 0x12 {
                return Err(Error::NonSha256Certhash);
            }
            let Ok(remote_certificate_sha256) = <&[u8; 32]>::try_from(multihash.data_ref()) else {
                return Err(Error::InvalidMultihashLength);
            };
            AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                port,
                remote_certificate_sha256,
            })
        }

        _ => return Err(Error::UnknownCombination),
    })
}

#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Unknown combination of protocols.
    UnknownCombination,

    /// Multiaddress contains a domain name that isn't UTF-8.
    ///
    /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
    /// >           string. Any binary data can be used as a domain name, provided it follows
    /// >           a few restrictions (notably its length). However, in this context, we
    /// >           automatically consider as non-supported a multiaddress that contains a
    /// >           non-UTF-8 domain name, for the sake of simplicity.
    NonUtf8DomainName(str::Utf8Error),

    /// Multiaddr contains a `/certhash` components whose multihash isn't using SHA-256, but the
    /// rest of the multiaddr requires SHA-256.
    NonSha256Certhash,

    /// Multiaddr contains a multihash whose length doesn't match its hash algorithm.
    InvalidMultihashLength,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use smoldot::libp2p::multihash::Multihash;

    fn pin(code: u8, len: u8) -> Protocol<Vec<u8>> {
        let mut bytes = vec![code, len];
        bytes.extend(core::iter::repeat_n(7, usize::from(len)));
        Protocol::Certhash(Multihash::from_bytes(bytes).unwrap())
    }

    #[test]
    fn webtransport_addresses() {
        for host in ["/ip4/127.0.0.1", "/ip6/::1"] {
            for count in [1, 3] {
                let mut addr: Multiaddr = format!("{host}/udp/40000/quic-v1/webtransport")
                    .parse()
                    .unwrap();
                for _ in 0..count {
                    addr.push(pin(0x12, 32));
                }
                let text = addr.to_string();
                assert_eq!(text.parse::<Multiaddr>().unwrap(), addr);
                let AddressOrMultiStreamAddress::MultiStreamAddress(parsed) =
                    multiaddr_to_address(&addr).unwrap()
                else {
                    panic!()
                };
                assert_eq!(
                    ConnectionType::from(&parsed),
                    if host.starts_with("/ip4") {
                        ConnectionType::WebTransportIpv4
                    } else {
                        ConnectionType::WebTransportIpv6
                    }
                );
                let MultiStreamAddress::WebTransport {
                    port, cert_hashes, ..
                } = parsed
                else {
                    panic!()
                };
                assert_eq!(port, 40000);
                assert_eq!(cert_hashes.as_ref(), vec![[7; 32]; count]);
            }
        }
    }

    #[test]
    fn malformed_webtransport_addresses() {
        for prefix in [
            "/ip4/127.0.0.1/udp/40000/quic-v1/webtransport",
            "/ip6/::1/udp/40000/quic-v1/webtransport",
        ] {
            let addr: Multiaddr = prefix.parse().unwrap();
            assert!(multiaddr_to_address(&addr).is_err());
            for (code, len) in [(0x13, 32), (0x12, 31), (0x12, 33)] {
                let mut invalid = addr.clone();
                invalid.push(pin(code, len));
                assert!(multiaddr_to_address(&invalid).is_err());
            }
            let mut trailing = addr.clone();
            trailing.push(pin(0x12, 32));
            trailing.push(Protocol::<Vec<u8>>::Ws);
            assert!(multiaddr_to_address(&trailing).is_err());
        }
        for prefix in [
            "/dns/localhost/udp/40000/quic-v1/webtransport",
            "/ip4/127.0.0.1/tcp/40000/quic-v1/webtransport",
            "/ip4/127.0.0.1/udp/40000/webtransport/quic-v1",
        ] {
            let mut addr: Multiaddr = prefix.parse().unwrap();
            addr.push(pin(0x12, 32));
            assert!(multiaddr_to_address(&addr).is_err());
        }
    }

    #[test]
    fn legacy_addresses() {
        for text in [
            "/ip4/127.0.0.1/tcp/80",
            "/ip6/::1/tcp/80/ws",
            "/dns/localhost/tcp/443/tls/ws",
        ] {
            assert!(multiaddr_to_address(&text.parse().unwrap()).is_ok());
        }
        let mut rtc: Multiaddr = "/ip4/127.0.0.1/udp/40000/webrtc-direct".parse().unwrap();
        rtc.push(pin(0x12, 32));
        assert!(matches!(
            multiaddr_to_address(&rtc),
            Ok(AddressOrMultiStreamAddress::MultiStreamAddress(
                MultiStreamAddress::WebRtc { .. }
            ))
        ));
        rtc.push(pin(0x12, 32));
        assert!(multiaddr_to_address(&rtc).is_err());
    }
}
