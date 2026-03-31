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

use alloc::vec::Vec;
use core::hash::{BuildHasher, Hasher};

use super::statement::Topic;

use fastbloom::DefaultHasher as BloomDefaultHasher;

// TODO: We should configure it in the statement-protocol config
const BLOOM_FALSE_POS_RATE: f64 = 0.01;

/// Maximum number of bits allowed in a bloom filter received from the network.
/// 1 MiB (the notification size budget) = 8_388_608 bits.
const MAX_BLOOM_BITS: usize = 1024 * 1024 * 8;

/// Maximum number of hash functions allowed.
/// Optimal hash count is `(bits / items) * ln(2)`. With the minimum allocation of 64 bits
/// and 1 expected item this yields ~44, so the limit must be at least that high. 64 covers all
/// practical configurations while preventing CPU abuse from peers.
pub(crate) const MAX_NUM_HASHES: u32 = 64;

/// Wraps `fastbloom::DefaultHasher` to force `write_usize`/`write_isize` to always emit
/// 8-byte LE values, ensuring identical bloom filter bits on wasm32 and 64-bit native targets.
#[derive(Clone, Debug)]
struct PortableBuildHasher(BloomDefaultHasher);

impl PortableBuildHasher {
    fn seeded(seed: u128) -> Self {
        Self(BloomDefaultHasher::seeded(&seed.to_le_bytes()))
    }
}

impl BuildHasher for PortableBuildHasher {
    type Hasher = PortableHasher;

    fn build_hasher(&self) -> Self::Hasher {
        PortableHasher(self.0.build_hasher())
    }
}

#[derive(Clone)]
struct PortableHasher(<BloomDefaultHasher as BuildHasher>::Hasher);

impl Hasher for PortableHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0.write(&(i as u64).to_le_bytes());
    }

    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.0.write(&(i as i64).to_le_bytes());
    }
}

struct EncodedBloomFilter {
    seed: u128,
    num_hashes: u32,
    bits: Vec<u64>,
}

impl EncodedBloomFilter {
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&self.num_hashes.to_le_bytes());
        out.extend_from_slice(crate::util::encode_scale_compact_usize(self.bits.len()).as_ref());
        for &word in &self.bits {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeAffinityFilterError> {
        if data.len() < 20 {
            return Err(DecodeAffinityFilterError);
        }
        let seed = u128::from_le_bytes(<[u8; 16]>::try_from(&data[..16]).unwrap());
        let num_hashes = u32::from_le_bytes(<[u8; 4]>::try_from(&data[16..20]).unwrap());
        let rest = &data[20..];
        let (rest, bits_len) =
            crate::util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>(rest)
                .map_err(|_| DecodeAffinityFilterError)?;
        if rest.len() != bits_len * 8 {
            return Err(DecodeAffinityFilterError);
        }
        let mut bits = Vec::with_capacity(bits_len);
        for chunk in rest.chunks_exact(8) {
            bits.push(u64::from_le_bytes(<[u8; 8]>::try_from(chunk).unwrap()));
        }
        Ok(EncodedBloomFilter {
            seed,
            num_hashes,
            bits,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AffinityFilter {
    bloom: fastbloom::BloomFilter<PortableBuildHasher>,
    seed: u128,
}

impl AffinityFilter {
    pub fn new(seed: u128, false_pos: f64, expected_items: usize) -> Self {
        let bloom = fastbloom::BloomFilter::with_false_pos(false_pos)
            .hasher(PortableBuildHasher::seeded(seed))
            .expected_items(expected_items);
        AffinityFilter { bloom, seed }
    }

    pub fn with_default_fpr(seed: u128, expected_items: usize) -> Self {
        Self::new(seed, BLOOM_FALSE_POS_RATE, expected_items)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeAffinityFilterError> {
        let encoded = EncodedBloomFilter::decode(data)?;
        if encoded.bits.is_empty() {
            return Err(DecodeAffinityFilterError);
        }
        if encoded.bits.len() * u64::BITS as usize > MAX_BLOOM_BITS {
            return Err(DecodeAffinityFilterError);
        }
        if encoded.num_hashes == 0 || encoded.num_hashes > MAX_NUM_HASHES {
            return Err(DecodeAffinityFilterError);
        }
        let bloom = fastbloom::BloomFilter::from_vec(encoded.bits)
            .hasher(PortableBuildHasher::seeded(encoded.seed))
            .hashes(encoded.num_hashes);
        Ok(AffinityFilter {
            bloom,
            seed: encoded.seed,
        })
    }

    pub fn insert(&mut self, topic: &[u8; 32]) {
        self.bloom.insert(topic);
    }

    pub fn contains(&self, topic: &[u8; 32]) -> bool {
        self.bloom.contains(topic)
    }

    pub fn matches_statement(&self, topics: &[&Topic]) -> bool {
        if topics.is_empty() {
            return true;
        }
        topics.iter().any(|t| self.bloom.contains(t))
    }

    pub fn encode_to_vec(&self) -> Vec<u8> {
        debug_assert!((1..=MAX_NUM_HASHES).contains(&self.bloom.num_hashes()));
        let encoded = EncodedBloomFilter {
            seed: self.seed,
            num_hashes: self.bloom.num_hashes(),
            bits: self.bloom.as_slice().to_vec(),
        };
        encoded.encode_to_vec()
    }

    pub fn match_all(seed: u128) -> Self {
        let bits = alloc::vec![u64::MAX; 16];
        let bloom = fastbloom::BloomFilter::from_vec(bits)
            .hasher(PortableBuildHasher::seeded(seed))
            .hashes(1);
        AffinityFilter { bloom, seed }
    }
}

#[derive(Debug, derive_more::Display, Clone)]
#[display("Invalid bloom filter encoding")]
pub struct DecodeAffinityFilterError;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: u128 = 0x5EED_5EED_5EED_5EED;

    const MAX_BLOOM_WORDS: usize = MAX_BLOOM_BITS / u64::BITS as usize;

    #[test]
    fn affinity_filter_roundtrip() {
        let topic1 = [0x01u8; 32];
        let topic2 = [0x02u8; 32];
        let topic3 = [0x03u8; 32];

        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, 2);
        filter.insert(&topic1);
        filter.insert(&topic2);

        let encoded = filter.encode_to_vec();
        let decoded = AffinityFilter::decode(&encoded).unwrap();

        assert!(decoded.contains(&topic1));
        assert!(decoded.contains(&topic2));
        assert!(!decoded.contains(&topic3));
    }

    #[test]
    fn matches_statement_no_topics_always_matches() {
        let bloom = fastbloom::BloomFilter::with_false_pos(BLOOM_FALSE_POS_RATE)
            .hasher(PortableBuildHasher::seeded(TEST_SEED))
            .expected_items(10);
        let filter = AffinityFilter {
            bloom,
            seed: TEST_SEED,
        };
        assert!(filter.matches_statement(&[]));
    }

    #[test]
    fn matches_statement_single_matching_topic() {
        let topic: [u8; 32] = [0xAA; 32];
        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, 10);
        filter.insert(&topic);
        assert!(filter.matches_statement(&[&topic]));
    }

    #[test]
    fn matches_statement_single_non_matching_topic() {
        let topic_in_filter: [u8; 32] = [0xAA; 32];
        let topic_on_stmt: [u8; 32] = [0xBB; 32];
        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, 10);
        filter.insert(&topic_in_filter);
        assert!(!filter.matches_statement(&[&topic_on_stmt]));
    }

    #[test]
    fn matches_statement_multiple_topics_any_semantics() {
        let topic_aa: [u8; 32] = [0xAA; 32];
        let topic_bb: [u8; 32] = [0xBB; 32];
        let topic_cc: [u8; 32] = [0xCC; 32];

        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, 10);
        filter.insert(&topic_bb);

        assert!(filter.matches_statement(&[&topic_aa, &topic_bb]));
        assert!(!filter.matches_statement(&[&topic_aa, &topic_cc]));
    }

    #[test]
    fn num_hashes_is_within_substrate_limit() {
        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, 1);
        filter.insert(&[0xAA; 32]);
        let encoded = filter.encode_to_vec();
        let num_hashes = u32::from_le_bytes(<[u8; 4]>::try_from(&encoded[16..20]).unwrap());
        assert!(
            (1..=MAX_NUM_HASHES).contains(&num_hashes),
            "num_hashes {num_hashes} out of allowed range 1..={MAX_NUM_HASHES}"
        );
    }

    #[test]
    fn decode_rejects_empty_bits() {
        let encoded = EncodedBloomFilter {
            seed: TEST_SEED,
            num_hashes: 7,
            bits: vec![],
        };
        let bytes = encoded.encode_to_vec();
        assert!(AffinityFilter::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_oversized_bits() {
        let encoded = EncodedBloomFilter {
            seed: TEST_SEED,
            num_hashes: 7,
            bits: vec![0u64; MAX_BLOOM_WORDS + 1],
        };
        let bytes = encoded.encode_to_vec();
        assert!(AffinityFilter::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_zero_num_hashes() {
        let encoded = EncodedBloomFilter {
            seed: TEST_SEED,
            num_hashes: 0,
            bits: vec![0u64; 16],
        };
        let bytes = encoded.encode_to_vec();
        assert!(AffinityFilter::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_excessive_num_hashes() {
        let encoded = EncodedBloomFilter {
            seed: TEST_SEED,
            num_hashes: u32::MAX,
            bits: vec![0u64; 16],
        };
        let bytes = encoded.encode_to_vec();
        assert!(AffinityFilter::decode(&bytes).is_err());
    }

    #[test]
    fn decode_accepts_valid_bounds() {
        let encoded = EncodedBloomFilter {
            seed: TEST_SEED,
            num_hashes: MAX_NUM_HASHES,
            bits: vec![0u64; MAX_BLOOM_WORDS],
        };
        let bytes = encoded.encode_to_vec();
        assert!(AffinityFilter::decode(&bytes).is_ok());
    }

    #[test]
    fn large_roundtrip() {
        const TOTAL: usize = 100_000;
        const SET_COUNT: usize = TOTAL / 10;

        let items: Vec<[u8; 32]> = (0..TOTAL)
            .map(|i| {
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                key
            })
            .collect();

        let mut filter = AffinityFilter::new(TEST_SEED, BLOOM_FALSE_POS_RATE, SET_COUNT);
        for item in &items[..SET_COUNT] {
            filter.insert(item);
        }

        let expected: Vec<bool> = items.iter().map(|item| filter.contains(item)).collect();
        for i in 0..SET_COUNT {
            assert!(expected[i], "inserted item {i} must be present");
        }

        let encoded = filter.encode_to_vec();
        let decoded = AffinityFilter::decode(&encoded).expect("decoding should succeed");

        for (i, item) in items.iter().enumerate() {
            assert_eq!(decoded.contains(item), expected[i], "mismatch for item {i}");
        }
    }
}
