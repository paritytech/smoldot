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

#![cfg(test)]

use super::{DownloadTree, NextNecessaryDownload};
use crate::header;

use core::time::Duration;

// TODO: this test tests nothing
#[test]
fn basic() {
    let finalized_header = header::HeaderRef {
        extrinsics_root: &[0; 32],
        number: 0,
        parent_hash: &[0; 32],
        state_root: &[0; 32],
        digest: header::DigestRef::empty(),
    }
    .scale_encoding_vec();

    let _tree = DownloadTree::<Duration>::from_finalized_block(finalized_header);
}

#[test]
fn invalid_header_accepted() {
    let mut tree = DownloadTree::from_finalized_block(vec![0xde, 0xad, 0xde, 0xad]);
    assert!(matches!(
        tree.next_necessary_download(&Duration::from_secs(0)),
        NextNecessaryDownload::NotReady { .. }
    ));
}

// TODO: needs actual tests
