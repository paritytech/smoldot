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

use smoldot::libp2p::{
    multiaddr::{Multiaddr, Protocol},
    multihash::Multihash,
};

use super::{Address, ConnectionType, DnsFamily, MultiStreamAddress};
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
        ) => AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port,
            remote_certificate_sha256: certhash_sha256(&multihash)?,
        }),

        (
            Protocol::Ip6(ip),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
            ip: IpAddr::V6(Ipv6Addr::from(ip)),
            port,
            remote_certificate_sha256: certhash_sha256(&multihash)?,
        }),
        (
            dns @ (Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr)),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtcDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            family: match dns {
                Protocol::Dns(_) => DnsFamily::Any,
                Protocol::Dns4(_) => DnsFamily::Ipv4,
                Protocol::Dns6(_) => DnsFamily::Ipv6,
                _ => unreachable!(),
            },
            port,
            remote_certificate_sha256: certhash_sha256(&multihash)?,
        }),
        _ => return Err(Error::UnknownCombination),
    })
}

/// Extracts the SHA-256 hash out of the multihash of a `/certhash` component.
fn certhash_sha256<'a>(multihash: &Multihash<&'a [u8]>) -> Result<&'a [u8; 32], Error> {
    if multihash.hash_algorithm_code() != 0x12 {
        return Err(Error::NonSha256Certhash);
    }
    <&[u8; 32]>::try_from(multihash.data_ref()).map_err(|_| Error::InvalidMultihashLength)
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
    use super::{AddressOrMultiStreamAddress, Error, multiaddr_to_address};
    use crate::platform::{ConnectionType, DnsFamily, MultiStreamAddress};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use smoldot::libp2p::multiaddr::Multiaddr;

    /// SHA-256 certhash of a real `webrtc-direct` bootnode.
    const CERTHASH: &str = "uEiBsqkcr8pOaNjl6px_v1nBatWMfXB9C_sU8fDat3mZWfQ";

    fn multistream(multiaddr: &Multiaddr) -> MultiStreamAddress<'_> {
        match multiaddr_to_address(multiaddr).unwrap() {
            AddressOrMultiStreamAddress::MultiStreamAddress(addr) => addr,
            AddressOrMultiStreamAddress::Address(addr) => {
                panic!("expected a multistream address, got {addr:?}")
            }
        }
    }

    fn cert_of(addr: &MultiStreamAddress) -> [u8; 32] {
        match addr {
            MultiStreamAddress::WebRtc {
                remote_certificate_sha256,
                ..
            }
            | MultiStreamAddress::WebRtcDns {
                remote_certificate_sha256,
                ..
            } => **remote_certificate_sha256,
        }
    }

    #[test]
    fn webrtc_with_ip_address() {
        let ip4: Multiaddr = format!("/ip4/1.2.3.4/udp/30333/webrtc-direct/certhash/{CERTHASH}")
            .parse()
            .unwrap();
        let parsed = multistream(&ip4);
        assert!(matches!(
            parsed,
            MultiStreamAddress::WebRtc { ip: IpAddr::V4(ip), port: 30333, .. }
                if ip == Ipv4Addr::new(1, 2, 3, 4)
        ));
        assert_eq!(ConnectionType::from(&parsed), ConnectionType::WebRtcIpv4);

        let ip6: Multiaddr = format!("/ip6/::1/udp/30333/webrtc-direct/certhash/{CERTHASH}")
            .parse()
            .unwrap();
        let parsed = multistream(&ip6);
        assert!(matches!(
            parsed,
            MultiStreamAddress::WebRtc { ip: IpAddr::V6(ip), port: 30333, .. }
                if ip == Ipv6Addr::LOCALHOST
        ));
        assert_eq!(ConnectionType::from(&parsed), ConnectionType::WebRtcIpv6);
    }

    #[test]
    fn webrtc_with_domain_name() {
        let ip4: Multiaddr = format!("/ip4/1.2.3.4/udp/30333/webrtc-direct/certhash/{CERTHASH}")
            .parse()
            .unwrap();
        let expected_cert = cert_of(&multistream(&ip4));

        for (protocol, family) in [
            ("dns", DnsFamily::Any),
            ("dns4", DnsFamily::Ipv4),
            ("dns6", DnsFamily::Ipv6),
        ] {
            let multiaddr: Multiaddr =
                format!("/{protocol}/example.com/udp/30333/webrtc-direct/certhash/{CERTHASH}")
                    .parse()
                    .unwrap();
            let parsed = multistream(&multiaddr);
            assert_eq!(
                parsed,
                MultiStreamAddress::WebRtcDns {
                    hostname: "example.com",
                    family,
                    port: 30333,
                    remote_certificate_sha256: &expected_cert,
                },
                "{protocol}"
            );
            assert_eq!(ConnectionType::from(&parsed), ConnectionType::WebRtcDns);
        }
    }

    #[test]
    fn webrtc_rejected_combinations() {
        // `dnsaddr` is never dialed directly.
        let multiaddr: Multiaddr =
            format!("/dnsaddr/example.com/udp/1/webrtc-direct/certhash/{CERTHASH}")
                .parse()
                .unwrap();
        assert!(matches!(
            multiaddr_to_address(&multiaddr),
            Err(Error::UnknownCombination)
        ));

        // A certhash is mandatory.
        let multiaddr: Multiaddr = "/dns/example.com/udp/1/webrtc-direct".parse().unwrap();
        assert!(matches!(
            multiaddr_to_address(&multiaddr),
            Err(Error::UnknownCombination)
        ));

        // SHA-1 multihash (code 0x11, 20 zero bytes), base64url without padding.
        let sha1_certhash = format!("u{}{}", "ERQ", "A".repeat(27));
        for host in ["dns/example.com", "ip4/1.2.3.4"] {
            let multiaddr: Multiaddr =
                format!("/{host}/udp/1/webrtc-direct/certhash/{sha1_certhash}")
                    .parse()
                    .unwrap();
            assert!(
                matches!(
                    multiaddr_to_address(&multiaddr),
                    Err(Error::NonSha256Certhash)
                ),
                "{host}"
            );
        }
    }
}
