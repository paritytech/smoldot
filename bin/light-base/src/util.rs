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

/// Iterator combinator. Truncates the given `char`-yielding iterator to the given number of
/// elements, and if the limit is reached adds a `…` at the end.
pub fn truncate_str_iter(
    input: impl Iterator<Item = char>,
    limit: usize,
) -> impl Iterator<Item = char> {
    struct Iter<I>(I, usize, bool, usize);

    impl<I: Iterator<Item = char>> Iterator for Iter<I> {
        type Item = char;

        fn next(&mut self) -> Option<Self::Item> {
            if self.2 {
                return None;
            }

            if self.1 >= self.3 {
                self.2 = true;
                if self.0.next().is_some() {
                    return Some('…');
                } else {
                    return None;
                }
            }

            self.1 += 1;
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            // Returns `size_hint()` of the inner iterator, after adding 1 to the maximum
            let (min, max) = self.0.size_hint();
            let max = max.and_then(|m| m.checked_add(1));
            (min, max)
        }
    }

    Iter(input, 0, false, limit)
}
