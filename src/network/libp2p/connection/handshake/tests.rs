// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg(test)]

use super::{Handshake, NoiseKey};

#[test]
fn handshake_basic_works() {
    fn test_with_buffer_sizes(size1: usize, size2: usize) {
        let key1 = NoiseKey::new(&rand::random());
        let key2 = NoiseKey::new(&rand::random());

        let mut handshake1 = Handshake::new(true);
        let mut handshake2 = Handshake::new(false);

        let mut buf_1_to_2 = Vec::new();
        let mut buf_2_to_1 = Vec::new();

        while !matches!(
            (&handshake1, &handshake2),
            (Handshake::Success { .. }, Handshake::Success { .. })
        ) {
            match handshake1 {
                Handshake::Success { .. } => {}
                Handshake::NoiseKeyRequired(req) => handshake1 = req.resume(&key1).into(),
                Handshake::Healthy(nego) => {
                    if buf_1_to_2.is_empty() {
                        buf_1_to_2.resize(size1, 0);
                        let (updated, num_read, written) =
                            nego.read_write(&buf_2_to_1, &mut buf_1_to_2).unwrap();
                        handshake1 = updated;
                        for _ in 0..num_read {
                            buf_2_to_1.remove(0);
                        }
                        buf_1_to_2.truncate(written);
                    } else {
                        let (updated, num_read, _) = nego.read_write(&buf_2_to_1, &mut []).unwrap();
                        handshake1 = updated;
                        for _ in 0..num_read {
                            buf_2_to_1.remove(0);
                        }
                    }
                }
            }

            match handshake2 {
                Handshake::Success { .. } => {}
                Handshake::NoiseKeyRequired(req) => handshake2 = req.resume(&key2).into(),
                Handshake::Healthy(nego) => {
                    if buf_2_to_1.is_empty() {
                        buf_2_to_1.resize(size2, 0);
                        let (updated, num_read, written) =
                            nego.read_write(&buf_1_to_2, &mut buf_2_to_1).unwrap();
                        handshake2 = updated;
                        for _ in 0..num_read {
                            buf_1_to_2.remove(0);
                        }
                        buf_2_to_1.truncate(written);
                    } else {
                        let (updated, num_read, _) = nego.read_write(&buf_1_to_2, &mut []).unwrap();
                        handshake2 = updated;
                        for _ in 0..num_read {
                            buf_1_to_2.remove(0);
                        }
                    }
                }
            }
        }
    }

    test_with_buffer_sizes(256, 256);
    // TODO: not passing
    //test_with_buffer_sizes(1, 1);
    //test_with_buffer_sizes(1, 2048);
    //test_with_buffer_sizes(2048, 1);
}
