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

/**
 * Deterministically generate the DER of the X.509 certificate corresponding to the
 * provided PeerId.
 *
 * @param peerId Bytes representation of a PeerId. If you have a string version (for example
 * `12Kwoo...` or `Qm...`), then you need to base58-decode it.
 */
export default function(peerId: ArrayBuffer): ArrayBuffer {
    throw new Error("Not implemented");
}
