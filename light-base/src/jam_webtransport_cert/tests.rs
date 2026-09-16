// Smoldot
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;

fn key(seed: u8) -> P256PeerId {
    let secret = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
    let encoded = secret.public_key().to_encoded_point(true);
    let x = encoded.as_bytes()[1..].try_into().unwrap();
    let id = P256PeerId::from_text(&coordinate_text(&x, encoded.as_bytes()[0] == 3)).unwrap();
    assert_eq!(id.x(), &x);
    assert_eq!(id.y_odd(), encoded.as_bytes()[0] == 3);
    assert_eq!(
        id.to_uncompressed_sec1().as_slice(),
        secret.public_key().to_encoded_point(false).as_bytes()
    );
    id
}

// Encode arbitrary coordinates without constructing an unchecked peer ID.
fn coordinate_text(x: &[u8; 32], y_odd: bool) -> String {
    let mut text = String::from(if y_odd { "o" } else { "v" });
    for symbol in 0..52 {
        let mut value = 0;
        for bit in 0..5 {
            let position = symbol * 5 + bit;
            if position < 256 {
                value |= ((x[position / 8] >> (position % 8)) & 1) << bit;
            }
        }
        text.push(char::from(ALPHABET[usize::from(value)]));
    }
    text
}

struct Subject(Vec<u8>);

impl rcgen::PublicKeyData for Subject {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Signer;

impl rcgen::PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        panic!("rcgen must not request the fake issuer's public key")
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for Signer {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(vec![0; 64])
    }
}

// Builds the certificate with rcgen, as PolkaJam does, with independent u128 time arithmetic.
fn reference_der(id: &P256PeerId, period: u64) -> Vec<u8> {
    let dn = |common_name: &str| {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        dn
    };
    let date = |seconds: u128| {
        time::OffsetDateTime::from_unix_timestamp(seconds.min(253_402_300_799).try_into().unwrap())
            .unwrap()
    };
    let mut params = rcgen::CertificateParams::new(vec![id.to_text()]).unwrap();
    params.serial_number = Some(period.into());
    params.distinguished_name = dn("jam");
    params.not_before = date((u128::from(period) * 864_000).saturating_sub(86_400));
    params.not_after = date((u128::from(period) + 1) * 864_000 + 86_400);
    let mut issuer = rcgen::CertificateParams::new(Vec::new()).unwrap();
    issuer.distinguished_name = dn(&id.to_text());
    params
        .signed_by(
            &Subject(id.to_uncompressed_sec1().to_vec()),
            &rcgen::Issuer::new(issuer, Signer),
        )
        .unwrap()
        .der()
        .to_vec()
}

#[test]
fn text_round_trip_and_both_parities() {
    for seed in 1..=32 {
        for y_odd in [false, true] {
            let id = P256PeerId::from_text(&coordinate_text(key(seed).x(), y_odd)).unwrap();
            let text = id.to_text();
            assert_eq!(text.len(), 53);
            assert_eq!(text.starts_with('o'), y_odd);
            assert_eq!(P256PeerId::from_text(&text), Ok(id));
            assert_eq!(id.y_odd(), y_odd);
            let point = id.to_uncompressed_sec1();
            assert_eq!(point[0], 4);
            assert_eq!(&point[1..33], id.x());
            assert_eq!(point[64] & 1 == 1, y_odd);
            assert!(p256::PublicKey::from_sec1_bytes(&point).is_ok());
        }
    }
}

/// The `bootnodes_p256` example of JIP-4 is the generator, the public key of
/// the secret key 1, whose Y coordinate is odd.
#[test]
fn jip4_bootnodes_p256_example() {
    let text = "ol3fcnzh4mrqoe4txgpzhgscis75gq6fqnz2hdqs6bnokemdtcwfb";
    let mut secret = [0; 32];
    secret[31] = 1;
    let generator = p256::SecretKey::from_slice(&secret).unwrap().public_key();
    let id = P256PeerId::from_text(text).unwrap();
    assert!(id.y_odd());
    assert_eq!(
        id.to_uncompressed_sec1().as_slice(),
        generator.to_encoded_point(false).as_bytes()
    );
    assert_eq!(id.to_text(), text);
}

#[test]
fn malformed_text_and_invalid_points() {
    use P256PeerIdParseError::*;
    let id = key(1);
    let text = id.to_text();
    for s in ["", "o", &text[..52], &(text.clone() + "a")] {
        assert_eq!(P256PeerId::from_text(s), Err(BadLength));
    }
    assert_eq!(P256PeerId::from_text("é"), Err(BadCharacter));
    for prefix in [b'e', b'O', b'V', b'0'] {
        let mut bytes = text.clone().into_bytes();
        bytes[0] = prefix;
        assert_eq!(
            P256PeerId::from_text(core::str::from_utf8(&bytes).unwrap()),
            Err(BadPrefix)
        );
    }
    for position in 1..53 {
        for bad in [b'=', b'0', b'1', b'8', b'A', b' ', b'\0'] {
            let mut bytes = text.clone().into_bytes();
            bytes[position] = bad;
            assert_eq!(
                P256PeerId::from_text(core::str::from_utf8(&bytes).unwrap()),
                Err(BadCharacter)
            );
        }
    }
    for &last in &ALPHABET[2..] {
        let mut bytes = text.clone().into_bytes();
        bytes[52] = last;
        assert_eq!(
            P256PeerId::from_text(core::str::from_utf8(&bytes).unwrap()),
            Err(NonZeroTrailingBits)
        );
    }
    for y_odd in [false, true] {
        // X >= the field modulus, and a canonical X with no square-root Y.
        for x in [[255; 32], {
            let mut x = [0; 32];
            x[31] = 1;
            x
        }] {
            assert_eq!(
                P256PeerId::from_text(&coordinate_text(&x, y_odd)),
                Err(InvalidPoint)
            );
        }
    }
}

#[test]
fn canonical_text_mutations() {
    let original = key(7).to_text().into_bytes();
    for position in 0..53 {
        for byte in 0..=127 {
            let mut bytes = original.clone();
            bytes[position] = byte;
            let text = core::str::from_utf8(&bytes).unwrap();
            if let Ok(id) = P256PeerId::from_text(text) {
                assert_eq!(id.to_text(), text);
                assert!(p256::PublicKey::from_sec1_bytes(&id.to_uncompressed_sec1()).is_ok());
            }
        }
    }
}

#[test]
fn validity_boundaries() {
    assert_eq!(ValidityPeriod(0).begin().unix_timestamp(), 0);
    assert_eq!(ValidityPeriod(0).end().unix_timestamp(), 950_400);
    assert_eq!(ValidityPeriod(1).begin().unix_timestamp(), 777_600);
    for period in [0, 1, 2072, 2073, 292_289] {
        let boundary = period * PERIOD_SECS;
        assert_eq!(ValidityPeriod::from_unix_secs(boundary).0, period);
        assert_eq!(
            ValidityPeriod::from_unix_secs(boundary + PERIOD_SECS - 1).0,
            period
        );
        if period != 0 {
            assert_eq!(ValidityPeriod::from_unix_secs(boundary - 1).0, period - 1);
        }
    }
    for period in [u64::MAX / PERIOD_SECS, u64::MAX] {
        assert_eq!(
            ValidityPeriod(period).begin().unix_timestamp(),
            253_402_300_799
        );
        assert_eq!(
            ValidityPeriod(period).end().unix_timestamp(),
            253_402_300_799
        );
    }
    assert_eq!(der_time(date_time(0)), b"\x17\x0d700101000000Z");
    assert_eq!(der_time(date_time(951_782_400)), b"\x17\x0d000229000000Z");
    assert_eq!(der_time(date_time(2_524_607_999)), b"\x17\x0d491231235959Z");
    assert_eq!(
        der_time(date_time(2_524_608_000)),
        b"\x18\x0f20500101000000Z"
    );
    assert_eq!(der_time(date_time(u64::MAX)), b"\x18\x0f99991231235959Z");
}

#[test]
fn exact_rcgen_certificates() {
    for seed in [1, 2] {
        for y_odd in [false, true] {
            let id = P256PeerId::from_text(&coordinate_text(key(seed).x(), y_odd)).unwrap();
            // Epoch, serial widths, leap day, fixture periods, mixed UTC/generalized dates, and
            // saturation.
            for period in [
                0,
                1,
                0x7f,
                0x80,
                0xff,
                0x100,
                1101,
                2072,
                2073,
                2921,
                2922,
                0x8000,
                0x01_0000,
                293_288,
                293_289,
                u64::MAX / PERIOD_SECS,
                u64::MAX,
            ] {
                assert_eq!(
                    certificate_der(&id, ValidityPeriod(period)),
                    reference_der(&id, period),
                    "seed {seed}, odd {y_odd}, period {period}"
                );
            }
        }
    }
}

#[test]
fn hash_order_and_rotation() {
    let id = key(3);
    for now in [
        0,
        PERIOD_SECS - 1,
        PERIOD_SECS,
        2072 * PERIOD_SECS - 1,
        2072 * PERIOD_SECS,
        2072 * PERIOD_SECS + 1,
        u64::MAX,
    ] {
        let current = now / PERIOD_SECS;
        let expected = [current.saturating_sub(1), current, current + 1]
            .map(|p| <[u8; 32]>::from(sha2::Sha256::digest(reference_der(&id, p))));
        assert_eq!(certificate_hashes(&id, now), expected);
        assert!(expected.iter().all(|hash| hash != &[0; 32]));
    }
    let before = certificate_hashes(&id, 2072 * PERIOD_SECS - 1);
    let after = certificate_hashes(&id, 2072 * PERIOD_SECS);
    assert_eq!(before[1..], after[..2]);
}

/// PolkaJam's own vector for the current form, `web_transport_cert_vector` in
/// `crates/node/src/net/cert.rs`: secret key `[1; 32]`, validity period 2072.
#[test]
fn polkajam_certificate_vector() {
    let id = key(1);
    assert_eq!(
        id.to_text(),
        "vpd4xdkksbst3rws2vjgmol2bkibjlnenafxetaoak5k44kqskwfa"
    );
    let expected = hex::decode(concat!(
        "3082017130820123a00302010202020818300506032b65703040313e303c0603",
        "5504030c357670643478646b6b736273743372777332766a676d6f6c32626b69",
        "626a6c6e656e6166786574616f616b356b34346b71736b776661301e170d3236",
        "303932333030303030305a170d3236313030353030303030305a300e310c300a",
        "06035504030c036a616d3059301306072a8648ce3d020106082a8648ce3d0301",
        "07034200046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2b",
        "ce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989",
        "cef71c144aa344304230400603551d110439303782357670643478646b6b7362",
        "73743372777332766a676d6f6c32626b69626a6c6e656e6166786574616f616b",
        "356b34346b71736b776661300506032b65700341000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000",
    ))
    .unwrap();
    let der = certificate_der(&id, ValidityPeriod(2072));
    assert_eq!(der, expected);
    assert_eq!(
        certificate_hashes(&id, 2072 * PERIOD_SECS)[1],
        <[u8; 32]>::from(sha2::Sha256::digest(&der))
    );
}

/// The serial cases of PolkaJam's `web_transport_serial_is_minimal_der_integer`, and the ends.
#[test]
fn serial_is_minimal_der_integer() {
    for (serial, content) in [
        (0, &[0x00][..]),
        (1, &[0x01]),
        (0x7f, &[0x7f]),
        (0x80, &[0x00, 0x80]),
        (0xff, &[0x00, 0xff]),
        (0x100, &[0x01, 0x00]),
        (2072, &[0x08, 0x18]),
        (0x8000, &[0x00, 0x80, 0x00]),
        (0x01_0000, &[0x01, 0x00, 0x00]),
        (
            u64::MAX >> 1,
            &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (
            u64::MAX,
            &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ] {
        assert_eq!(serial_integer(serial), content, "serial {serial}");
    }
}

/// Every node and period gets its own issuer and serial pair.
#[test]
fn distinct_issuer_and_serial() {
    let (one, two) = (key(1), key(2));
    let (period, next) = (ValidityPeriod(2072), ValidityPeriod(2073));
    let issuer_and_serial = |der: &[u8]| {
        // The certificate's and the TBS's headers, with long-form lengths; then v3 (5 bytes),
        // the serial, the signature algorithm and the issuer name.
        let tbs = &der[6 + usize::from(der[5] & 0x7f)..];
        let serial_end = 5 + 2 + usize::from(tbs[6]);
        let issuer_start = serial_end + ED25519_ALGORITHM.len();
        let issuer_end = issuer_start + 2 + usize::from(tbs[issuer_start + 1]);
        (
            tbs[5..serial_end].to_vec(),
            tbs[issuer_start..issuer_end].to_vec(),
        )
    };
    let pairs = [(&one, period), (&one, next), (&two, period), (&two, next)]
        .map(|(id, period)| issuer_and_serial(&certificate_der(id, period)));
    for (index, pair) in pairs.iter().enumerate() {
        assert!(!pairs[..index].contains(pair));
    }
    assert_eq!(pairs[0].0, pairs[2].0);
    assert_eq!(pairs[0].1, pairs[1].1);
    assert_eq!(pairs[0].1, name(one.to_text().as_bytes()));
    assert_eq!(pairs[0].0, [2, 2, 0x08, 0x18]);
}

#[test]
fn exact_certificate_vectors() {
    let json = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/jam_webtransport_cert/fixtures/cert_vector.json"),
    )
    .unwrap();
    #[derive(serde::Deserialize)]
    struct Vector {
        p256_id_text: String,
        period: u64,
        der_hex: String,
        sha256_hex: String,
    }
    let decode = |s: &str| hex::decode(s).unwrap();
    let vectors: Vec<Vector> = serde_json::from_slice(&json).unwrap();
    let mut keys = std::collections::BTreeSet::new();
    let mut pairs = std::collections::BTreeSet::new();
    for vector in &vectors {
        let id = P256PeerId::from_text(&vector.p256_id_text).unwrap();
        assert_eq!(id.to_text(), vector.p256_id_text);
        let der = certificate_der(&id, ValidityPeriod(vector.period));
        assert_eq!(der, decode(&vector.der_hex));
        assert_eq!(der, reference_der(&id, vector.period));
        assert_eq!(
            sha2::Sha256::digest(&der).as_slice(),
            decode(&vector.sha256_hex)
        );
        for (slot, now_period) in [
            (0, vector.period + 1),
            (1, vector.period),
            (2, vector.period - 1),
        ] {
            assert_eq!(
                certificate_hashes(&id, now_period * PERIOD_SECS)[slot].as_slice(),
                decode(&vector.sha256_hex)
            );
        }
        keys.insert(&vector.p256_id_text);
        assert!(pairs.insert((&vector.p256_id_text, vector.period)));
    }
    assert!(keys.len() >= 2);
    for key in keys {
        assert!(pairs.iter().filter(|(k, _)| *k == key).count() >= 2);
    }
}
