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

use super::nibble;
use core::{cmp, fmt, iter, slice};

/// Encodes the components of a node value into the node value itself.
///
/// This function returns an iterator of buffers. The actual node value is the concatenation of
/// these buffers put together.
///
/// > **Note**: The returned iterator might contain a reference to the storage value and children
/// >           values in the [`Decoded`]. By returning an iterator of buffers, we avoid copying
/// >           these storage value and children values.
///
/// This encoding is independent of the trie version.
pub fn encode(
    decoded: Decoded<'_>,
) -> impl Iterator<Item = impl AsRef<[u8]> + '_ + Clone> + Clone + '_ {
    // The return value is composed of three parts:
    // - Before the storage value.
    // - The storage value (which can be empty).
    // - The children nodes.

    // Contains the encoding before the storage value.
    let mut before_storage_value: Vec<u8> = Vec::with_capacity(decoded.partial_key.len() / 2 + 32);

    let has_children = decoded.children.iter().any(Option::is_some);

    // We first push the node header.
    // See https://spec.polkadot.network/#defn-node-header
    {
        let (first_byte_msb, pk_len_first_byte_bits): (u8, _) =
            match (has_children, decoded.storage_value) {
                (false, StorageValue::Unhashed(_)) => (0b01, 6),
                (true, StorageValue::None) => (0b10, 6),
                (true, StorageValue::Unhashed(_)) => (0b11, 6),
                (false, StorageValue::Hashed(_)) => (0b001, 5),
                (true, StorageValue::Hashed(_)) => (0b0001, 4),
                // TODO: it's invalid to have a non-empty partial key in that situation; this isn't problematic in practice
                (false, StorageValue::None) => (0, 6),
            };

        let max_representable_in_first_byte = (1 << pk_len_first_byte_bits) - 1;
        let first_byte = (first_byte_msb << pk_len_first_byte_bits)
            | u8::try_from(cmp::min(
                decoded.partial_key.len(),
                max_representable_in_first_byte,
            ))
            .unwrap();
        before_storage_value.push(first_byte);

        // Note that if the partial key length is exactly equal to `pk_len_first_byte_bits`, we
        // need to push a `0` afterwards in order to avoid an ambiguity. Similarly, if
        // `remain_pk_len` is at any point equal to 255, we must push an additional `0`
        // afterwards.
        let mut remain_pk_len = decoded
            .partial_key
            .len()
            .checked_sub(max_representable_in_first_byte);
        while let Some(pk_len_inner) = remain_pk_len {
            before_storage_value.push(u8::try_from(cmp::min(pk_len_inner, 255)).unwrap());
            remain_pk_len = pk_len_inner.checked_sub(255);
        }
    }

    // We then push the partial key.
    before_storage_value.extend(nibble::nibbles_to_bytes_prefix_extend(
        decoded.partial_key.clone(),
    ));

    // After the partial key, the node value optionally contains a bitfield of child nodes.
    if has_children {
        before_storage_value.extend_from_slice(&decoded.children_bitmap().to_le_bytes());
    }

    // Then, the storage value.
    let storage_value = match decoded.storage_value {
        StorageValue::Hashed(hash) => &hash[..],
        StorageValue::None => &[][..],
        StorageValue::Unhashed(storage_value) => {
            before_storage_value.extend_from_slice(
                crate::util::encode_scale_compact_usize(storage_value.len()).as_ref(),
            );
            storage_value
        }
    };

    // Finally, the children node values.
    let children_nodes = decoded
        .children
        .into_iter()
        .filter_map(|c| c)
        .flat_map(|child_value| {
            let size = crate::util::encode_scale_compact_usize(child_value.len());
            [either::Left(size), either::Right(child_value)].into_iter()
        });

    // The return value is the combination of these components.
    iter::once(either::Left(before_storage_value))
        .chain(iter::once(either::Right(storage_value)))
        .map(either::Left)
        .chain(children_nodes.map(either::Right))
}

/// Decodes a node value found in a proof into its components.
///
/// This can decode nodes no matter their version.
pub fn decode(mut node_value: &[u8]) -> Result<Decoded, Error> {
    if node_value.is_empty() {
        return Err(Error::Empty);
    }

    // See https://spec.polkadot.network/#defn-node-header
    let (has_children, storage_value_hashed, pk_len_first_byte_bits) = match node_value[0] >> 6 {
        0b00 => {
            if (node_value[0] >> 5) == 0b001 {
                (false, Some(true), 5)
            } else if (node_value[0] >> 4) == 0b0001 {
                (true, Some(true), 4)
            } else if node_value[0] == 0 {
                (false, None, 6)
            } else {
                return Err(Error::InvalidHeaderBits);
            }
        }
        0b10 => (true, None, 6),
        0b01 => (false, Some(false), 6),
        0b11 => (true, Some(false), 6),
        _ => unreachable!(),
    };

    // Length of the partial key, in nibbles.
    let pk_len = {
        let mut accumulator = usize::from(node_value[0] & ((1 << pk_len_first_byte_bits) - 1));
        node_value = &node_value[1..];
        let mut continue_iter = accumulator == ((1 << pk_len_first_byte_bits) - 1);
        while continue_iter {
            if node_value.is_empty() {
                return Err(Error::PartialKeyLenTooShort);
            }
            continue_iter = node_value[0] == 255;
            accumulator = accumulator
                .checked_add(usize::from(node_value[0]))
                .ok_or(Error::PartialKeyLenOverflow)?;
            node_value = &node_value[1..];
        }
        accumulator
    };

    // No children and no storage value can only indicate the root of an empty trie, in which case
    // a non-empty partial key is invalid.
    if pk_len != 0 && !has_children && storage_value_hashed.is_none() {
        return Err(Error::EmptyTrieWithPartialKey);
    }

    // Iterator to the partial key found in the node value of `proof_iter`.
    let partial_key = {
        // Length of the partial key, in bytes.
        let pk_len_bytes = if pk_len == 0 {
            0
        } else {
            1 + ((pk_len - 1) / 2)
        };
        if node_value.len() < pk_len_bytes {
            return Err(Error::PartialKeyTooShort);
        }

        let pk = &node_value[..pk_len_bytes];
        node_value = &node_value[pk_len_bytes..];

        if (pk_len % 2) == 1 && (pk[0] & 0xf0) != 0 {
            return Err(Error::InvalidPartialKeyPadding);
        }

        pk
    };

    // After the partial key, the node value optionally contains a bitfield of child nodes.
    let children_bitmap = if has_children {
        if node_value.len() < 2 {
            return Err(Error::ChildrenBitmapTooShort);
        }
        let val = u16::from_le_bytes(<[u8; 2]>::try_from(&node_value[..2]).unwrap());
        if val == 0 {
            return Err(Error::ZeroChildrenBitmap);
        }
        node_value = &node_value[2..];
        val
    } else {
        0
    };

    // Now at the value that interests us.
    let storage_value = match storage_value_hashed {
        Some(false) => {
            let (node_value_update, len) = crate::util::nom_scale_compact_usize(node_value)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::StorageValueLenDecode)?;
            node_value = node_value_update;
            if node_value.len() < len {
                return Err(Error::StorageValueTooShort);
            }
            let storage_value = &node_value[..len];
            node_value = &node_value[len..];
            StorageValue::Unhashed(storage_value)
        }
        Some(true) => {
            if node_value.len() < 32 {
                return Err(Error::StorageValueTooShort);
            }
            let storage_value_hash = <&[u8; 32]>::try_from(&node_value[..32]).unwrap();
            node_value = &node_value[32..];
            StorageValue::Hashed(storage_value_hash)
        }
        None => StorageValue::None,
    };

    let mut children = [None; 16];
    for (n, child) in children.iter_mut().enumerate() {
        if children_bitmap & (1 << n) == 0 {
            continue;
        }

        // Find the Merkle value of that child in `node_value`.
        let (node_value_update, len) = crate::util::nom_scale_compact_usize(node_value)
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::ChildLenDecode)?;
        node_value = node_value_update;
        if node_value.len() < len {
            return Err(Error::ChildrenTooShort);
        }

        *child = Some(&node_value[..len]);
        node_value = &node_value[len..];
    }

    if !node_value.is_empty() {
        return Err(Error::TooLong);
    }

    Ok(Decoded {
        partial_key: PartialKey {
            inner: nibble::bytes_to_nibbles(partial_key.iter().copied()),
            skip_first: (pk_len % 2) == 1,
        },
        children,
        storage_value,
    })
}

/// Decoded node value. Returned by [`decode`] or passed as parameter to [`encode`].
#[derive(Debug, Clone)]
pub struct Decoded<'a> {
    /// Iterator to the nibbles of the partial key of the node.
    pub partial_key: PartialKey<'a>,

    /// All 16 possible children. `Some` if a child is present, and `None` otherwise. The `&[u8]`
    /// can be:
    ///
    /// - Of length 32, in which case the slice is the hash of the node value of the child (also
    ///   known as the Merkle value).
    /// - Empty when decoding a compact trie proof.
    /// - Of length inferior to 32, in which case the slice is directly the node value.
    ///
    pub children: [Option<&'a [u8]>; 16],

    /// Storage value of this node.
    pub storage_value: StorageValue<'a>,
}

impl<'a> Decoded<'a> {
    /// Returns a bits map of the children that are present, as found in the node value.
    pub fn children_bitmap(&self) -> u16 {
        let mut out = 0u16;
        for n in 0..16 {
            if self.children[n].is_none() {
                continue;
            }
            out |= 1 << n;
        }
        out
    }
}

/// See [`Decoded::storage_value`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum StorageValue<'a> {
    /// Storage value of the item is present in the node value.
    Unhashed(&'a [u8]),
    /// BLAKE2 hash of the storage value of the item is present in the node value.
    Hashed(&'a [u8; 32]),
    /// Item doesn't have any storage value.
    None,
}

/// Iterator to the nibbles of the partial key. See [`Decoded::partial_key`].
#[derive(Clone)]
pub struct PartialKey<'a> {
    inner: nibble::BytesToNibbles<iter::Copied<slice::Iter<'a, u8>>>,
    skip_first: bool,
}

impl<'a> Iterator for PartialKey<'a> {
    type Item = nibble::Nibble;

    fn next(&mut self) -> Option<nibble::Nibble> {
        loop {
            let nibble = self.inner.next()?;
            if self.skip_first {
                debug_assert_eq!(u8::from(nibble), 0);
                self.skip_first = false;
                continue;
            }
            break Some(nibble);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut len = self.inner.len();
        if self.skip_first {
            len -= 1;
        }
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for PartialKey<'a> {}

impl<'a> fmt::Debug for PartialKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const HEX_TABLE: &[u8] = b"0123456789abcdef";
        write!(f, "0x")?;
        for nibble in self.clone() {
            let chr = HEX_TABLE[usize::from(u8::from(nibble))];
            write!(f, "{}", char::from(chr))?;
        }
        Ok(())
    }
}

/// Possible error returned by [`decode`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Node value is empty.
    Empty,
    /// Bits in the header have an invalid format.
    InvalidHeaderBits,
    /// Node value ends while parsing partial key length.
    PartialKeyLenTooShort,
    /// Length of partial key is too large to be reasonable.
    PartialKeyLenOverflow,
    /// Node value ends within partial key.
    PartialKeyTooShort,
    /// If partial key is of uneven length, then it must be padded with `0`.
    InvalidPartialKeyPadding,
    /// End of data within the children bitmap.
    ChildrenBitmapTooShort,
    /// The children bitmap is equal to 0 despite the header indicating the presence of children.
    ZeroChildrenBitmap,
    /// Error while decoding length of child.
    ChildLenDecode,
    /// Node value ends within a child value.
    ChildrenTooShort,
    /// Error while decoding length of storage value.
    StorageValueLenDecode,
    /// Node value ends within the storage value.
    StorageValueTooShort,
    /// Node value is longer than expected.
    TooLong,
    /// Node value indicates that it is the root of an empty trie but contains a non-empty partial
    /// key.
    EmptyTrieWithPartialKey,
}

#[cfg(test)]
mod tests {
    use super::super::nibble;

    #[test]
    fn basic() {
        let encoded_bytes = &[
            194, 99, 192, 0, 0, 128, 129, 254, 111, 21, 39, 188, 215, 18, 139, 76, 128, 157, 108,
            33, 139, 232, 34, 73, 0, 21, 202, 54, 18, 71, 145, 117, 47, 222, 189, 93, 119, 68, 128,
            108, 211, 105, 98, 122, 206, 246, 73, 77, 237, 51, 77, 26, 166, 1, 52, 179, 173, 43,
            89, 219, 104, 196, 190, 208, 128, 135, 177, 13, 185, 111, 175,
        ];

        let decoded = super::decode(encoded_bytes).unwrap();

        assert_eq!(
            proof_node_codec::encode(decoded.clone()).fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            }),
            encoded_bytes
        );
        assert_eq!(
            decoded.partial_key.collect::<Vec<_>>(),
            vec![
                nibble::Nibble::try_from(0x6).unwrap(),
                nibble::Nibble::try_from(0x3).unwrap()
            ]
        );
        assert_eq!(
            decoded.storage_value,
            proof_node_codec::StorageValue::Unhashed(&[][..])
        );

        assert_eq!(decoded.children.iter().filter(|c| c.is_some()).count(), 2);
        assert_eq!(
            decoded.children[6],
            Some(
                &[
                    129, 254, 111, 21, 39, 188, 215, 18, 139, 76, 128, 157, 108, 33, 139, 232, 34,
                    73, 0, 21, 202, 54, 18, 71, 145, 117, 47, 222, 189, 93, 119, 68
                ][..]
            )
        );
        assert_eq!(
            decoded.children[7],
            Some(
                &[
                    108, 211, 105, 98, 122, 206, 246, 73, 77, 237, 51, 77, 26, 166, 1, 52, 179,
                    173, 43, 89, 219, 104, 196, 190, 208, 128, 135, 177, 13, 185, 111, 175
                ][..]
            )
        );
    }
}
