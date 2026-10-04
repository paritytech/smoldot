// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use crate::jam::{codec, test_support::json_bytes};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// The network's `C(8)` value, from the CE 129 state-read capture.
fn captured() -> Vec<ValidatorKey> {
    let capture: serde_json::Value =
        serde_json::from_str(include_str!("../trie/fixtures/polkajam-ce129.json")).unwrap();
    let params = crate::jam::params::Params::from_protocol_parameters(&json_bytes(
        &capture["protocol_parameters"],
    ))
    .unwrap();
    codec::decode_active_validators(&params, &json_bytes(&capture["expected_validators_hex"]))
        .unwrap()
}

fn with_metadata(metadata: [u8; 128]) -> ValidatorKey {
    ValidatorKey {
        bandersnatch: [1; 32],
        ed25519: [2; 32],
        bls: [3; 144],
        metadata,
    }
}

#[test]
fn captured_dev_records_parse_to_loopback_ports_and_p256_keys() {
    let validators = captured();
    assert_eq!(validators.len(), 6);
    let endpoints: Vec<_> = validators
        .iter()
        .map(ValidatorEndpoint::from_validator)
        .collect();
    for (index, endpoint) in endpoints.iter().enumerate() {
        assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port, 40000 + u16::try_from(index).unwrap());
        assert_eq!(endpoint.ed25519, validators[index].ed25519);
        let (x, _) = endpoint.p256.unwrap();
        assert_eq!(x[..], validators[index].metadata[19..51]);
        // Reserved bytes are zero; the parser ignores them either way.
        assert!(validators[index].metadata[51..].iter().all(|b| *b == 0));
    }
    // Parity bytes as captured: 1, 1, 0, 1, 1, 0.
    assert_eq!(
        endpoints
            .iter()
            .map(|e| e.p256.unwrap().1)
            .collect::<Vec<_>>(),
        [true, true, false, true, true, false]
    );
    // Validator 0 is node0, Ed25519 id `eecgwpgw…2utb`.
    assert_eq!(hex::encode(&endpoints[0].ed25519[..4]), "4418fb8c");
}

#[test]
fn missing_or_malformed_p256_field_yields_none() {
    let record = captured().remove(0);

    let mut zero = record.metadata;
    zero[18..51].fill(0);
    let endpoint = ValidatorEndpoint::from_validator(&with_metadata(zero));
    assert_eq!(endpoint.p256, None);
    assert_eq!(endpoint.port, 40000, "the address survives a missing key");

    for parity in [2, 3, 0x80, 0xff] {
        let mut bad = record.metadata;
        bad[18] = parity;
        assert_eq!(
            ValidatorEndpoint::from_validator(&with_metadata(bad)).p256,
            None
        );
    }

    // A zero X with odd parity is still "no key".
    let mut odd_zero = [0; 128];
    odd_zero[18] = 1;
    assert_eq!(
        ValidatorEndpoint::from_validator(&with_metadata(odd_zero)).p256,
        None
    );
}

#[test]
fn ipv6_stays_ipv6_and_unset_records_have_port_zero() {
    let address: Ipv6Addr = "2001:db8::7".parse().unwrap();
    let mut metadata = [0; 128];
    metadata[..16].copy_from_slice(&address.octets());
    metadata[16..18].copy_from_slice(&40123u16.to_le_bytes());
    let endpoint = ValidatorEndpoint::from_validator(&with_metadata(metadata));
    assert_eq!(endpoint.ip, IpAddr::V6(address));
    assert_eq!(endpoint.port, 40123);
    assert_eq!(endpoint.ed25519, [2; 32]);

    let unset = ValidatorEndpoint::from_validator(&with_metadata([0; 128]));
    assert_eq!(unset.ip, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert_eq!(unset.port, 0);
    assert_eq!(unset.p256, None);

    // `::ffff:a.b.c.d` is unmapped; `::a.b.c.d` (IPv4-compatible) is not.
    let mut mapped = [0; 128];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..16].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(
        ValidatorEndpoint::from_validator(&with_metadata(mapped)).ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    let mut compatible = [0; 128];
    compatible[12..16].copy_from_slice(&[10, 0, 0, 1]);
    assert!(
        ValidatorEndpoint::from_validator(&with_metadata(compatible))
            .ip
            .is_ipv6()
    );
}
