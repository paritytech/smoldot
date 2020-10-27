// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

fn main() {
    prost_build::compile_protos(
        &[
            "src/network/discovery/kademlia/dht.proto",
            "src/network/connection/noise/payload.proto",
            "src/network/peer_id/keys.proto",
            "src/network/protocol/api.v1.proto",
            "src/network/protocol/finality.v1.proto",
            "src/network/protocol/light.v1.proto",
        ],
        &["src"],
    )
    .unwrap();
}
