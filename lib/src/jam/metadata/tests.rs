// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use core::net::Ipv4Addr;

/// D2's committed CE 129 capture carries the dev network's `C(8)` value.
fn captured() -> (Params, Vec<u8>) {
    let capture: serde_json::Value =
        serde_json::from_str(include_str!("../trie/fixtures/polkajam-ce129.json")).unwrap();
    let unhex = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let params = Params::from_protocol_parameters(&unhex(&capture["protocol_parameters"])).unwrap();
    (params, unhex(&capture["expected_validators_hex"]))
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
    let (params, value) = captured();
    let validators = decode_active_set(&params, &value).unwrap();
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
        // Reserved bytes are zero today; the parser ignores them either way.
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
    // Validator 0 is node0: Ed25519 `eecgwpgw…2utb` (fixtures/local-network.md).
    assert_eq!(hex::encode(&endpoints[0].ed25519[..4]), "4418fb8c");
}

#[test]
fn missing_or_malformed_p256_field_yields_none() {
    let (params, value) = captured();
    let record = decode_active_set(&params, &value).unwrap().remove(0);

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

    // A zero X with odd parity is still "no key": PolkaJam never writes it.
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

#[test]
fn active_set_decoder_is_the_bounded_c8_decoder() {
    let (params, value) = captured();
    assert_eq!(
        decode_active_set(&params, &value),
        codec::decode_active_validators(&params, &value)
    );
    assert!(decode_active_set(&params, &value[..value.len() - 1]).is_err());
    let mut extra = value.clone();
    extra.push(0);
    assert!(decode_active_set(&params, &extra).is_err());
    // More records than `max_validators` are refused before allocation.
    let mut oversized = vec![u8::try_from(params.max_validators + 3).unwrap()];
    oversized.resize(1 + 336 * usize::from(params.max_validators + 3), 0);
    assert!(decode_active_set(&params, &oversized).is_err());
}
