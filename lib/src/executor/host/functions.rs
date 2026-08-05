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

//! Contains the list of all host functions, in other words functions that the runtime is allowed
//! to call.

use crate::executor::vm;

macro_rules! host_functions {
    ($($ext:ident,)*) => {
        /// List of possible host functions.
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        pub enum HostFunction {
            $(
                $ext,
            )*
        }

        impl HostFunction {
            /// Returns a host function given its name.
            pub fn by_name(name: &str) -> Option<Self> {
                $(
                    if name == stringify!($ext) {
                        return Some(HostFunction::$ext);
                    }
                )*
                None
            }

            /// Returns the name of this host function.
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        HostFunction::$ext => stringify!($ext),
                    )*
                }
            }
        }
    };
}

host_functions! {
    ext_storage_set_version_1,
    ext_storage_get_version_1,
    ext_storage_read_version_1,
    ext_storage_clear_version_1,
    ext_storage_exists_version_1,
    ext_storage_clear_prefix_version_1,
    ext_storage_clear_prefix_version_2,
    ext_storage_root_version_1,
    ext_storage_root_version_2,
    ext_storage_changes_root_version_1,
    ext_storage_next_key_version_1,
    ext_storage_append_version_1,
    ext_storage_start_transaction_version_1,
    ext_storage_rollback_transaction_version_1,
    ext_storage_commit_transaction_version_1,
    ext_storage_proof_size_storage_proof_size_version_1,
    ext_default_child_storage_get_version_1,
    ext_default_child_storage_read_version_1,
    ext_default_child_storage_storage_kill_version_1,
    ext_default_child_storage_storage_kill_version_2,
    ext_default_child_storage_storage_kill_version_3,
    ext_default_child_storage_clear_prefix_version_1,
    ext_default_child_storage_clear_prefix_version_2,
    ext_default_child_storage_set_version_1,
    ext_default_child_storage_clear_version_1,
    ext_default_child_storage_exists_version_1,
    ext_default_child_storage_next_key_version_1,
    ext_default_child_storage_root_version_1,
    ext_default_child_storage_root_version_2,
    ext_crypto_ed25519_public_keys_version_1,
    ext_crypto_ed25519_generate_version_1,
    ext_crypto_ed25519_sign_version_1,
    ext_crypto_ed25519_verify_version_1,
    ext_crypto_ed25519_batch_verify_version_1,
    ext_crypto_sr25519_public_keys_version_1,
    ext_crypto_sr25519_generate_version_1,
    ext_crypto_sr25519_sign_version_1,
    ext_crypto_sr25519_verify_version_1,
    ext_crypto_sr25519_verify_version_2,
    ext_crypto_sr25519_batch_verify_version_1,
    ext_crypto_ecdsa_generate_version_1,
    ext_crypto_ecdsa_sign_version_1,
    ext_crypto_ecdsa_public_keys_version_1,
    ext_crypto_ecdsa_verify_version_1,
    ext_crypto_ecdsa_verify_version_2,
    ext_crypto_ecdsa_sign_prehashed_version_1,
    ext_crypto_ecdsa_verify_prehashed_version_1,
    ext_crypto_ecdsa_batch_verify_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_2,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_1,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_2,
    ext_crypto_start_batch_verify_version_1,
    ext_crypto_finish_batch_verify_version_1,
    ext_hashing_keccak_256_version_1,
    ext_hashing_keccak_512_version_1,
    ext_hashing_sha2_256_version_1,
    ext_hashing_blake2_128_version_1,
    ext_hashing_blake2_256_version_1,
    ext_hashing_twox_64_version_1,
    ext_hashing_twox_128_version_1,
    ext_hashing_twox_256_version_1,
    ext_offchain_index_set_version_1,
    ext_offchain_index_clear_version_1,
    ext_offchain_is_validator_version_1,
    ext_offchain_submit_transaction_version_1,
    ext_offchain_network_state_version_1,
    ext_offchain_timestamp_version_1,
    ext_offchain_sleep_until_version_1,
    ext_offchain_random_seed_version_1,
    ext_offchain_local_storage_set_version_1,
    ext_offchain_local_storage_compare_and_set_version_1,
    ext_offchain_local_storage_get_version_1,
    ext_offchain_local_storage_clear_version_1,
    ext_offchain_http_request_start_version_1,
    ext_offchain_http_request_add_header_version_1,
    ext_offchain_http_request_write_body_version_1,
    ext_offchain_http_response_wait_version_1,
    ext_offchain_http_response_headers_version_1,
    ext_offchain_http_response_read_body_version_1,
    ext_trie_blake2_256_root_version_1,
    ext_trie_blake2_256_root_version_2,
    ext_trie_blake2_256_ordered_root_version_1,
    ext_trie_blake2_256_ordered_root_version_2,
    ext_trie_keccak_256_root_version_1,
    ext_trie_keccak_256_root_version_2,
    ext_trie_keccak_256_ordered_root_version_1,
    ext_trie_keccak_256_ordered_root_version_2,
    ext_trie_blake2_256_verify_proof_version_1,
    ext_trie_blake2_256_verify_proof_version_2,
    ext_trie_keccak_256_verify_proof_version_1,
    ext_trie_keccak_256_verify_proof_version_2,
    ext_host_calls_bls12_381_multi_miller_loop_version_1,
    ext_host_calls_bls12_381_final_exponentiation_version_1,
    ext_host_calls_bls12_381_msm_g1_version_1,
    ext_host_calls_bls12_381_msm_g2_version_1,
    ext_host_calls_bls12_381_mul_g1_version_1,
    ext_host_calls_bls12_381_mul_g2_version_1,
    ext_host_calls_ed_on_bls12_381_bandersnatch_msm_version_1,
    ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1,
    ext_host_calls_pallas_msm_version_1,
    ext_host_calls_pallas_mul_version_1,
    ext_host_calls_vesta_msm_version_1,
    ext_host_calls_vesta_mul_version_1,
    ext_misc_print_num_version_1,
    ext_misc_print_utf8_version_1,
    ext_misc_print_hex_version_1,
    ext_misc_runtime_version_version_1,
    ext_allocator_malloc_version_1,
    ext_allocator_free_version_1,
    ext_logging_log_version_1,
    ext_logging_max_level_version_1,
    ext_panic_handler_abort_on_panic_version_1,
    ext_transaction_index_index_version_1,
    ext_transaction_index_renew_version_1,
    ext_statement_store_remove_by_version_1,
}

impl HostFunction {
    /// Returns the signature of this host function.
    // TODO: make this a `const fn` function
    pub fn signature(&self) -> vm::Signature {
        match *self {
            HostFunction::ext_storage_set_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_storage_get_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_read_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_clear_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_storage_exists_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_storage_clear_prefix_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_storage_clear_prefix_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_root_version_1 => crate::signature!(() => vm::ValueType::I64),
            HostFunction::ext_storage_root_version_2 => {
                crate::signature!((vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_changes_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_next_key_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_storage_append_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_storage_start_transaction_version_1 => crate::signature!(() => ()),
            HostFunction::ext_storage_rollback_transaction_version_1 => crate::signature!(() => ()),
            HostFunction::ext_storage_commit_transaction_version_1 => crate::signature!(() => ()),
            HostFunction::ext_storage_proof_size_storage_proof_size_version_1 => {
                crate::signature!(() => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_get_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_read_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_storage_kill_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_default_child_storage_storage_kill_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_default_child_storage_storage_kill_version_3 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_default_child_storage_clear_prefix_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_set_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_default_child_storage_clear_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_default_child_storage_exists_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_default_child_storage_next_key_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_default_child_storage_root_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ed25519_public_keys_version_1 => {
                crate::signature!((vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ed25519_generate_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ed25519_sign_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ed25519_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ed25519_batch_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_sr25519_public_keys_version_1 => {
                crate::signature!((vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_sr25519_generate_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_sr25519_sign_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_sr25519_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_sr25519_verify_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_sr25519_batch_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ecdsa_generate_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ecdsa_sign_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ecdsa_public_keys_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ecdsa_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ecdsa_verify_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ecdsa_sign_prehashed_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_ecdsa_verify_prehashed_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_ecdsa_batch_verify_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32) => vm::ValueType::I64)
            }
            HostFunction::ext_crypto_start_batch_verify_version_1 => crate::signature!(() => ()),
            HostFunction::ext_crypto_finish_batch_verify_version_1 => {
                crate::signature!(() => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_keccak_256_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_keccak_512_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_sha2_256_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_blake2_128_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_blake2_256_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_twox_64_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_twox_128_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_hashing_twox_256_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_offchain_index_set_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_offchain_index_clear_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_offchain_is_validator_version_1 => {
                crate::signature!(() => vm::ValueType::I32)
            }
            HostFunction::ext_offchain_submit_transaction_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_network_state_version_1 => {
                crate::signature!(() => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_timestamp_version_1 => {
                crate::signature!(() => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_sleep_until_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_offchain_random_seed_version_1 => {
                crate::signature!(() => vm::ValueType::I32)
            }
            HostFunction::ext_offchain_local_storage_set_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_offchain_local_storage_compare_and_set_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_offchain_local_storage_get_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_local_storage_clear_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64) => ())
            }
            HostFunction::ext_offchain_http_request_start_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_http_request_add_header_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_http_request_write_body_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_http_response_wait_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_http_response_headers_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_offchain_http_response_read_body_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_trie_blake2_256_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_blake2_256_root_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_blake2_256_ordered_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_blake2_256_ordered_root_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_root_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_ordered_root_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_ordered_root_version_2 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_blake2_256_verify_proof_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_blake2_256_verify_proof_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_verify_proof_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_trie_keccak_256_verify_proof_version_2 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_host_calls_bls12_381_final_exponentiation_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_host_calls_bls12_381_multi_miller_loop_version_1
            | HostFunction::ext_host_calls_bls12_381_msm_g1_version_1
            | HostFunction::ext_host_calls_bls12_381_msm_g2_version_1
            | HostFunction::ext_host_calls_bls12_381_mul_g1_version_1
            | HostFunction::ext_host_calls_bls12_381_mul_g2_version_1
            | HostFunction::ext_host_calls_ed_on_bls12_381_bandersnatch_msm_version_1
            | HostFunction::ext_host_calls_ed_on_bls12_381_bandersnatch_mul_version_1
            | HostFunction::ext_host_calls_pallas_msm_version_1
            | HostFunction::ext_host_calls_pallas_mul_version_1
            | HostFunction::ext_host_calls_vesta_msm_version_1
            | HostFunction::ext_host_calls_vesta_mul_version_1 => {
                crate::signature!((vm::ValueType::I64, vm::ValueType::I64, vm::ValueType::I64) => vm::ValueType::I32)
            }
            HostFunction::ext_misc_print_num_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_misc_print_utf8_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_misc_print_hex_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_misc_runtime_version_version_1 => {
                crate::signature!((vm::ValueType::I64) => vm::ValueType::I64)
            }
            HostFunction::ext_allocator_malloc_version_1 => {
                crate::signature!((vm::ValueType::I32) => vm::ValueType::I32)
            }
            HostFunction::ext_allocator_free_version_1 => {
                crate::signature!((vm::ValueType::I32) => ())
            }
            HostFunction::ext_logging_log_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I64, vm::ValueType::I64) => ())
            }
            HostFunction::ext_logging_max_level_version_1 => {
                crate::signature!(() => vm::ValueType::I32)
            }
            HostFunction::ext_panic_handler_abort_on_panic_version_1 => {
                crate::signature!((vm::ValueType::I64) => ())
            }
            HostFunction::ext_transaction_index_index_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32, vm::ValueType::I32) => ())
            }
            HostFunction::ext_transaction_index_renew_version_1 => {
                crate::signature!((vm::ValueType::I32, vm::ValueType::I32) => ())
            }
            HostFunction::ext_statement_store_remove_by_version_1 => {
                crate::signature!((vm::ValueType::I32) => ())
            }
        }
    }
}
