// Smoldot
// Copyright (C) 2024  Pierre Krieger
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

// `ext_transaction_index_*` are no-ops on smoldot (light client has no offchain index), but
// they MUST consume their params with the correct wasm value types. The previous code read
// param 0 as a packed pointer-size (I64) and panicked the wasm executor the moment any
// substrate runtime actually called these functions (e.g. `pallet-transaction-storage::store`
// in a chopsticks replay). These tests exercise the param-reading path so a regression to
// the old shape would fault here instead of in production.

use super::super::{
    Config, HeapPages, HostVm, HostVmPrototype, StorageProofSizeBehavior, vm::ExecHint,
};
use super::with_core_version_custom_sections;

fn run_to_finished(module_bytes: Vec<u8>) {
    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(
            proto
                .run(
                    "test",
                    StorageProofSizeBehavior::proof_recording_disabled(),
                    b"",
                )
                .unwrap(),
        );

        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Finished(_) => break,
                other => panic!("unexpected HostVm state: {:?}", other),
            }
        }
    }
}

#[test]
fn ext_transaction_index_index_consumes_three_i32_params() {
    // Three I32s — extrinsic_index, content_size, content_hash_ptr — and 32 bytes of
    // (zeroed) memory at offset 0 for the hash. Test passes if the runtime entry point
    // returns without trapping; a regression to the `expect_pointer_size_raw!` shape would
    // panic in the macro because param 0 is I32, not I64.
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 16))
        (import "env" "ext_transaction_index_index_version_1"
            (func $tx_index (param i32 i32 i32)))
        (global (export "__heap_base") i32 (i32.const 1024))
        (func (export "test") (param i32 i32) (result i64)
            i32.const 7      ;; extrinsic_index
            i32.const 128    ;; content_size
            i32.const 0      ;; content_hash_ptr (points at 32 zero bytes)
            call $tx_index
            i64.const 0))
    "#,
        )
        .unwrap(),
    );

    run_to_finished(module_bytes);
}

#[test]
fn ext_transaction_index_renew_consumes_i32_and_hash_pointer() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 16))
        (import "env" "ext_transaction_index_renew_version_1"
            (func $tx_renew (param i32 i32)))
        (global (export "__heap_base") i32 (i32.const 1024))
        (func (export "test") (param i32 i32) (result i64)
            i32.const 3      ;; extrinsic_index
            i32.const 0      ;; content_hash_ptr
            call $tx_renew
            i64.const 0))
    "#,
        )
        .unwrap(),
    );

    run_to_finished(module_bytes);
}
