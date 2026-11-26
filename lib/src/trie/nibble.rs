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

use core::fmt;

/// A single nibble with four bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nibble(u8);

impl Nibble {
    /// Returns the equivalent of `Nibble::try_from(0).unwrap()`.
    pub fn zero() -> Self {
        Nibble(0)
    }

    /// Returns the equivalent of `Nibble::try_from(15).unwrap()`. It is the maximum possible value
    /// for a nibble.
    pub fn max() -> Self {
        Nibble(15)
    }

    /// Add the given number to the nibble. Returns `None` on overflow.
    pub fn checked_add(self, val: u8) -> Option<Self> {
        let new_nibble = self.0.checked_add(val)?;
        if new_nibble >= 16 {
            return None;
        }
        Some(Nibble(new_nibble))
    }

    /// Converts an ASCII hexadecimal digit (i.e. `0..9`, `a..f`, `A..F`) into a nibble.
    ///
    /// Returns `None` if `digit` is out of range.
    pub fn from_ascii_hex_digit(digit: u8) -> Option<Self> {
        if digit.is_ascii_digit() {
            Some(Nibble(digit - b'0'))
        } else if (b'a'..=b'f').contains(&digit) {
            Some(Nibble(10 + digit - b'a'))
        } else if (b'A'..=b'F').contains(&digit) {
            Some(Nibble(10 + digit - b'A'))
        } else {
            None
        }
    }
}

impl TryFrom<u8> for Nibble {
    type Error = NibbleFromU8Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        if val < 16 {
            Ok(Nibble(val))
        } else {
            Err(NibbleFromU8Error::TooLarge)
        }
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> u8 {
        nibble.0
    }
}

impl From<Nibble> for usize {
    fn from(nibble: Nibble) -> usize {
        usize::from(nibble.0)
    }
}

impl fmt::LowerHex for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Debug for Nibble {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// Error when building a [`Nibble`] from a `u8`.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum NibbleFromU8Error {
    /// The integer value is too large.
    #[display("Value is too large")]
    TooLarge,
}

/// Returns an iterator of all possible nibble values, in ascending order.
///
/// # Example
///
/// ```
/// assert_eq!(
///     smoldot::trie::all_nibbles().map(u8::from).collect::<Vec<_>>(),
///     &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
/// );
/// ```
pub fn all_nibbles() -> impl ExactSizeIterator<Item = Nibble> {
    (0..16).map(Nibble)
}

/// Turns an iterator of nibbles into an iterator of bytes.
///
/// If the number of nibbles is uneven, adds a `0` nibble at the end.
///
/// # Examples
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_suffix_extend};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap()];
/// assert_eq!(nibbles_to_bytes_suffix_extend(input.into_iter()).collect::<Vec<_>>(), &[0x5a]);
/// ```
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_suffix_extend};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap(), Nibble::try_from(0x9).unwrap()];
/// assert_eq!(nibbles_to_bytes_suffix_extend(input.into_iter()).collect::<Vec<_>>(), &[0x5a, 0x90]);
/// ```
pub fn nibbles_to_bytes_suffix_extend<I: Iterator<Item = Nibble>>(
    nibbles: I,
) -> impl Iterator<Item = u8> {
    struct Iter<I>(I);

    impl<I: Iterator<Item = Nibble>> Iterator for Iter<I> {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            let n1 = self.0.next()?;
            let n2 = self.0.next().unwrap_or(Nibble(0));
            let byte = (n1.0 << 4) | n2.0;
            Some(byte)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let (min, max) = self.0.size_hint();
            fn conv(n: usize) -> usize {
                // Add 1 to `n` in order to round up.
                n.saturating_add(1) / 2
            }
            (conv(min), max.map(conv))
        }
    }

    Iter(nibbles)
}

/// Turns an iterator of nibbles into an iterator of bytes.
///
/// If the number of nibbles is uneven, adds a `0` nibble at the beginning.
///
/// # Examples
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_prefix_extend};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap()];
/// assert_eq!(nibbles_to_bytes_prefix_extend(input.into_iter()).collect::<Vec<_>>(), &[0x5a]);
/// ```
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_prefix_extend};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap(), Nibble::try_from(0x9).unwrap()];
/// assert_eq!(nibbles_to_bytes_prefix_extend(input.into_iter()).collect::<Vec<_>>(), &[0x05, 0xa9]);
/// ```
pub fn nibbles_to_bytes_prefix_extend<I: ExactSizeIterator<Item = Nibble>>(
    nibbles: I,
) -> impl ExactSizeIterator<Item = u8> {
    struct Iter<I>(I, bool);

    impl<I: ExactSizeIterator<Item = Nibble>> Iterator for Iter<I> {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            let n1 = if self.1 {
                self.1 = false;
                Nibble(0)
            } else {
                self.0.next()?
            };
            let n2 = self.0.next()?;
            let byte = (n1.0 << 4) | n2.0;
            Some(byte)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let inner_len = self.0.len();
            let len = if self.1 {
                debug_assert_eq!(inner_len % 2, 1);
                (inner_len / 2) + 1
            } else {
                debug_assert_eq!(inner_len % 2, 0);
                inner_len / 2
            };
            (len, Some(len))
        }
    }

    impl<I: ExactSizeIterator<Item = Nibble>> ExactSizeIterator for Iter<I> {}

    let has_prefix_nibble = (nibbles.len() % 2) != 0;
    Iter(nibbles, has_prefix_nibble)
}

/// Turns an iterator of nibbles into an iterator of bytes.
///
/// If the number of nibbles is uneven, the last nibble is truncated.
///
/// # Examples
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_truncate};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap()];
/// assert_eq!(nibbles_to_bytes_truncate(input.into_iter()).collect::<Vec<_>>(), &[0x5a]);
/// ```
///
/// ```
/// use smoldot::trie::{Nibble, nibbles_to_bytes_truncate};
///
/// let input = [Nibble::try_from(0x5).unwrap(), Nibble::try_from(0xa).unwrap(), Nibble::try_from(0x9).unwrap()];
/// assert_eq!(nibbles_to_bytes_truncate(input.into_iter()).collect::<Vec<_>>(), &[0x5a]);
/// ```
pub fn nibbles_to_bytes_truncate<I: Iterator<Item = Nibble>>(
    nibbles: I,
) -> impl Iterator<Item = u8> {
    struct Iter<I>(I);

    impl<I: Iterator<Item = Nibble>> Iterator for Iter<I> {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            let n1 = self.0.next()?;
            let n2 = self.0.next()?;
            let byte = (n1.0 << 4) | n2.0;
            Some(byte)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let (min, max) = self.0.size_hint();
            fn conv(n: usize) -> usize {
                n / 2
            }
            (conv(min), max.map(conv))
        }
    }

    Iter(nibbles)
}

/// Turns an iterator of bytes into an iterator of nibbles corresponding to these bytes.
///
/// For each byte, the iterator yields a nibble containing the 4 most significant bits then a
/// nibble containing the 4 least significant bits.
pub fn bytes_to_nibbles<I>(bytes: I) -> BytesToNibbles<I> {
    BytesToNibbles {
        inner: bytes,
        next: None,
    }
}

/// Turns an iterator of bytes into an iterator of nibbles corresponding to these bytes.
#[derive(Debug, Copy, Clone)]
pub struct BytesToNibbles<I> {
    inner: I,
    next: Option<Nibble>,
}

impl<I: Iterator<Item = u8>> Iterator for BytesToNibbles<I> {
    type Item = Nibble;

    fn next(&mut self) -> Option<Nibble> {
        if let Some(next) = self.next.take() {
            return Some(next);
        }

        let byte = self.inner.next()?;
        self.next = Some(Nibble(byte & 0xf));
        Some(Nibble(byte >> 4))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.inner.size_hint();

        if self.next.is_some() {
            (
                min.saturating_mul(2).saturating_add(1),
                max.and_then(|max| max.checked_mul(2))
                    .and_then(|max| max.checked_add(1)),
            )
        } else {
            (
                min.saturating_mul(2),
                max.and_then(|max| max.checked_mul(2)),
            )
        }
    }
}

impl<I: ExactSizeIterator<Item = u8>> ExactSizeIterator for BytesToNibbles<I> {}

#[cfg(test)]
mod tests {
    use super::{Nibble, NibbleFromU8Error, bytes_to_nibbles};

    #[test]
    fn nibble_try_from() {
        assert_eq!(u8::from(Nibble::try_from(0).unwrap()), 0);
        assert_eq!(u8::from(Nibble::try_from(1).unwrap()), 1);
        assert_eq!(u8::from(Nibble::try_from(15).unwrap()), 15);

        assert!(matches!(
            Nibble::try_from(16),
            Err(NibbleFromU8Error::TooLarge)
        ));
        assert!(matches!(
            Nibble::try_from(255),
            Err(NibbleFromU8Error::TooLarge)
        ));
    }

    #[test]
    fn from_ascii_hex_digit_works() {
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'0').unwrap()), 0);
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'9').unwrap()), 9);
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'a').unwrap()), 10);
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'f').unwrap()), 15);
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'A').unwrap()), 10);
        assert_eq!(u8::from(Nibble::from_ascii_hex_digit(b'F').unwrap()), 15);
        assert!(Nibble::from_ascii_hex_digit(b'j').is_none());
        assert!(Nibble::from_ascii_hex_digit(b' ').is_none());
        assert!(Nibble::from_ascii_hex_digit(0).is_none());
        assert!(Nibble::from_ascii_hex_digit(255).is_none());
    }

    #[test]
    fn bytes_to_nibbles_works() {
        assert_eq!(
            bytes_to_nibbles([].iter().cloned()).collect::<Vec<_>>(),
            &[]
        );
        assert_eq!(
            bytes_to_nibbles([1].iter().cloned()).collect::<Vec<_>>(),
            &[Nibble::try_from(0).unwrap(), Nibble::try_from(1).unwrap()]
        );
        assert_eq!(
            bytes_to_nibbles([200].iter().cloned()).collect::<Vec<_>>(),
            &[
                Nibble::try_from(0xc).unwrap(),
                Nibble::try_from(0x8).unwrap()
            ]
        );
        assert_eq!(
            bytes_to_nibbles([80, 200, 9].iter().cloned()).collect::<Vec<_>>(),
            &[
                Nibble::try_from(5).unwrap(),
                Nibble::try_from(0).unwrap(),
                Nibble::try_from(0xc).unwrap(),
                Nibble::try_from(0x8).unwrap(),
                Nibble::try_from(0).unwrap(),
                Nibble::try_from(9).unwrap()
            ]
        );
    }

    #[test]
    fn bytes_to_nibbles_len() {
        assert_eq!(bytes_to_nibbles([].iter().cloned()).len(), 0);
        assert_eq!(bytes_to_nibbles([1].iter().cloned()).len(), 2);
        assert_eq!(bytes_to_nibbles([200].iter().cloned()).len(), 2);
        assert_eq!(
            bytes_to_nibbles([1, 2, 3, 4, 5, 6].iter().cloned()).len(),
            12
        );
    }
}
