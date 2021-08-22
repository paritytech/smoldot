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

use super::nibble;
use core::{convert::TryFrom as _, iter, slice};

/// Decodes a node value found in a proof into its components.
pub fn decode(mut node_value: &[u8]) -> Result<Decoded, Error> {
    if node_value.is_empty() {
        return Err(Error::Empty);
    }

    let has_children = (node_value[0] & 0x80) != 0;
    let has_storage_value = (node_value[0] & 0x40) != 0;

    // Length of the partial key, in nibbles.
    let pk_len = {
        let mut accumulator = usize::from(node_value[0] & 0b111111);
        node_value = &node_value[1..];
        let mut continue_iter = accumulator == 63;
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
        pk
    };

    // After the partial key, the node value optionally contains a bitfield of child nodes.
    let children_bitmap = if has_children {
        if node_value.len() < 2 {
            return Err(Error::ChildrenBitmapTooShort);
        }
        let val = u16::from_le_bytes(<[u8; 2]>::try_from(&node_value[..2]).unwrap());
        node_value = &node_value[2..];
        val
    } else {
        0
    };

    let mut children = [None; 16];
    for n in 0..16 {
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

        children[n] = Some(&node_value[..len]);
        node_value = &node_value[len..];
    }

    let storage_value = if has_storage_value {
        // Now at the value that interests us.
        let (node_value_update, len) = crate::util::nom_scale_compact_usize(node_value)
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::StorageValueLenDecode)?;
        node_value = node_value_update;
        if node_value.len() < len {
            return Err(Error::StorageValueTooShort);
        }
        if node_value.len() > len {
            return Err(Error::TooLong);
        }
        Some(node_value)
    } else if !node_value.is_empty() {
        return Err(Error::TooLong);
    } else {
        None
    };

    Ok(Decoded {
        partial_key: PartialKey {
            inner: nibble::bytes_to_nibbles(partial_key.iter().copied()),
            skip_first: (pk_len % 2) == 1,
        },
        children,
        storage_value,
    })
}

/// Decoded node value. Returned by [`decode`].
pub struct Decoded<'a> {
    /// Iterator to the nibbles of the partial key of the node.
    pub partial_key: PartialKey<'a>,

    /// All 16 possible children. `Some` if a child is present, and `None` otherwise. The `&[u8]`
    /// can be:
    ///
    /// - Of length 32, in which case the slice is the hash of the node value of the child (also
    ///   known as the merkle value).
    /// - Empty when decoding a compact trie proof.
    /// - Of length inferior to 32, in which case the slice is directly the node value.
    ///
    pub children: [Option<&'a [u8]>; 16],

    /// Storage value of this node, or `None` if there is no storage value.
    pub storage_value: Option<&'a [u8]>,
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

/// Possible error returned by [`decode`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Node value is empty.
    Empty,
    /// Node value ends while parsing partial key length.
    PartialKeyLenTooShort,
    /// Length of partial key is too large to be reasonable.
    PartialKeyLenOverflow,
    /// Node value ends within partial key.
    PartialKeyTooShort,
    /// End of data within the children bitmap.
    ChildrenBitmapTooShort,
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
}

// TODO: tests
