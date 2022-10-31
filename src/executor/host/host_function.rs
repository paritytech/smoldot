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

macro_rules! externalities {
    ($($ext:ident,)*) => {
        /// List of possible externalities.
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        pub enum HostFunction {
            $(
                $ext,
            )*
        }

        impl HostFunction {
            pub fn by_name(name: &str) -> Option<Self> {
                $(
                    if name == stringify!($ext) {
                        return Some(HostFunction::$ext);
                    }
                )*
                None
            }

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

externalities! {
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
    ext_storage_child_set_version_1,
    ext_storage_child_get_version_1,
    ext_storage_child_read_version_1,
    ext_storage_child_clear_version_1,
    ext_storage_child_storage_kill_version_1,
    ext_storage_child_exists_version_1,
    ext_storage_child_clear_prefix_version_1,
    ext_storage_child_root_version_1,
    ext_storage_child_next_key_version_1,
    ext_storage_start_transaction_version_1,
    ext_storage_rollback_transaction_version_1,
    ext_storage_commit_transaction_version_1,
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
    ext_crypto_sr25519_public_keys_version_1,
    ext_crypto_sr25519_generate_version_1,
    ext_crypto_sr25519_sign_version_1,
    ext_crypto_sr25519_verify_version_1,
    ext_crypto_sr25519_verify_version_2,
    ext_crypto_ecdsa_generate_version_1,
    ext_crypto_ecdsa_sign_version_1,
    ext_crypto_ecdsa_public_keys_version_1,
    ext_crypto_ecdsa_verify_version_1,
    ext_crypto_ecdsa_sign_prehashed_version_1,
    ext_crypto_ecdsa_verify_prehashed_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_1,
    ext_crypto_secp256k1_ecdsa_recover_version_2,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_1,
    ext_crypto_secp256k1_ecdsa_recover_compressed_version_2,
    ext_crypto_start_batch_verify_version_1,
    ext_crypto_finish_batch_verify_version_1,
    ext_hashing_keccak_256_version_1,
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
    ext_sandbox_instantiate_version_1,
    ext_sandbox_invoke_version_1,
    ext_sandbox_memory_new_version_1,
    ext_sandbox_memory_get_version_1,
    ext_sandbox_memory_set_version_1,
    ext_sandbox_memory_teardown_version_1,
    ext_sandbox_instance_teardown_version_1,
    ext_sandbox_get_global_val_version_1,
    ext_trie_blake2_256_root_version_1,
    ext_trie_blake2_256_root_version_2,
    ext_trie_blake2_256_ordered_root_version_1,
    ext_trie_blake2_256_ordered_root_version_2,
    ext_trie_keccak_256_ordered_root_version_1,
    ext_trie_keccak_256_ordered_root_version_2,
    ext_misc_print_num_version_1,
    ext_misc_print_utf8_version_1,
    ext_misc_print_hex_version_1,
    ext_misc_runtime_version_version_1,
    ext_allocator_malloc_version_1,
    ext_allocator_free_version_1,
    ext_logging_log_version_1,
    ext_logging_max_level_version_1,
}

impl HostFunction {
    pub fn num_parameters(&self) -> usize {
        match *self {
            HostFunction::ext_storage_set_version_1 => 2,
            HostFunction::ext_storage_get_version_1 => 1,
            HostFunction::ext_storage_read_version_1 => 3,
            HostFunction::ext_storage_clear_version_1 => 1,
            HostFunction::ext_storage_exists_version_1 => 1,
            HostFunction::ext_storage_clear_prefix_version_1 => 1,
            HostFunction::ext_storage_clear_prefix_version_2 => 2,
            HostFunction::ext_storage_root_version_1 => 0,
            HostFunction::ext_storage_root_version_2 => 1,
            HostFunction::ext_storage_changes_root_version_1 => 1,
            HostFunction::ext_storage_next_key_version_1 => 1,
            HostFunction::ext_storage_append_version_1 => 2,
            HostFunction::ext_storage_child_set_version_1 => todo!(),
            HostFunction::ext_storage_child_get_version_1 => todo!(),
            HostFunction::ext_storage_child_read_version_1 => todo!(),
            HostFunction::ext_storage_child_clear_version_1 => todo!(),
            HostFunction::ext_storage_child_storage_kill_version_1 => todo!(),
            HostFunction::ext_storage_child_exists_version_1 => todo!(),
            HostFunction::ext_storage_child_clear_prefix_version_1 => todo!(),
            HostFunction::ext_storage_child_root_version_1 => todo!(),
            HostFunction::ext_storage_child_next_key_version_1 => todo!(),
            HostFunction::ext_storage_start_transaction_version_1 => 0,
            HostFunction::ext_storage_rollback_transaction_version_1 => 0,
            HostFunction::ext_storage_commit_transaction_version_1 => 0,
            HostFunction::ext_default_child_storage_get_version_1 => todo!(),
            HostFunction::ext_default_child_storage_read_version_1 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_1 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_2 => todo!(),
            HostFunction::ext_default_child_storage_storage_kill_version_3 => todo!(),
            HostFunction::ext_default_child_storage_clear_prefix_version_1 => todo!(),
            HostFunction::ext_default_child_storage_clear_prefix_version_2 => todo!(),
            HostFunction::ext_default_child_storage_set_version_1 => todo!(),
            HostFunction::ext_default_child_storage_clear_version_1 => todo!(),
            HostFunction::ext_default_child_storage_exists_version_1 => todo!(),
            HostFunction::ext_default_child_storage_next_key_version_1 => todo!(),
            HostFunction::ext_default_child_storage_root_version_1 => todo!(),
            HostFunction::ext_default_child_storage_root_version_2 => todo!(),
            HostFunction::ext_crypto_ed25519_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_generate_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_sign_version_1 => todo!(),
            HostFunction::ext_crypto_ed25519_verify_version_1 => 3,
            HostFunction::ext_crypto_sr25519_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_generate_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_sign_version_1 => todo!(),
            HostFunction::ext_crypto_sr25519_verify_version_1 => 3,
            HostFunction::ext_crypto_sr25519_verify_version_2 => 3,
            HostFunction::ext_crypto_ecdsa_generate_version_1 => todo!(),
            HostFunction::ext_crypto_ecdsa_sign_version_1 => 2,
            HostFunction::ext_crypto_ecdsa_public_keys_version_1 => todo!(),
            HostFunction::ext_crypto_ecdsa_verify_version_1 => 3,
            HostFunction::ext_crypto_ecdsa_sign_prehashed_version_1 => 2,
            HostFunction::ext_crypto_ecdsa_verify_prehashed_version_1 => 3,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_1 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_version_2 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_1 => 2,
            HostFunction::ext_crypto_secp256k1_ecdsa_recover_compressed_version_2 => 2,
            HostFunction::ext_crypto_start_batch_verify_version_1 => 0,
            HostFunction::ext_crypto_finish_batch_verify_version_1 => 0,
            HostFunction::ext_hashing_keccak_256_version_1 => 1,
            HostFunction::ext_hashing_sha2_256_version_1 => todo!(),
            HostFunction::ext_hashing_blake2_128_version_1 => 1,
            HostFunction::ext_hashing_blake2_256_version_1 => 1,
            HostFunction::ext_hashing_twox_64_version_1 => 1,
            HostFunction::ext_hashing_twox_128_version_1 => 1,
            HostFunction::ext_hashing_twox_256_version_1 => 1,
            HostFunction::ext_offchain_index_set_version_1 => 2,
            HostFunction::ext_offchain_index_clear_version_1 => 1,
            HostFunction::ext_offchain_is_validator_version_1 => todo!(),
            HostFunction::ext_offchain_submit_transaction_version_1 => todo!(),
            HostFunction::ext_offchain_network_state_version_1 => todo!(),
            HostFunction::ext_offchain_timestamp_version_1 => todo!(),
            HostFunction::ext_offchain_sleep_until_version_1 => todo!(),
            HostFunction::ext_offchain_random_seed_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_set_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_compare_and_set_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_get_version_1 => todo!(),
            HostFunction::ext_offchain_local_storage_clear_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_start_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_add_header_version_1 => todo!(),
            HostFunction::ext_offchain_http_request_write_body_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_wait_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_headers_version_1 => todo!(),
            HostFunction::ext_offchain_http_response_read_body_version_1 => todo!(),
            HostFunction::ext_sandbox_instantiate_version_1 => todo!(),
            HostFunction::ext_sandbox_invoke_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_new_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_get_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_set_version_1 => todo!(),
            HostFunction::ext_sandbox_memory_teardown_version_1 => todo!(),
            HostFunction::ext_sandbox_instance_teardown_version_1 => todo!(),
            HostFunction::ext_sandbox_get_global_val_version_1 => todo!(),
            HostFunction::ext_trie_blake2_256_root_version_1 => 1,
            HostFunction::ext_trie_blake2_256_root_version_2 => 2,
            HostFunction::ext_trie_blake2_256_ordered_root_version_1 => 1,
            HostFunction::ext_trie_blake2_256_ordered_root_version_2 => 2,
            HostFunction::ext_trie_keccak_256_ordered_root_version_1 => todo!(),
            HostFunction::ext_trie_keccak_256_ordered_root_version_2 => todo!(),
            HostFunction::ext_misc_print_num_version_1 => 1,
            HostFunction::ext_misc_print_utf8_version_1 => 1,
            HostFunction::ext_misc_print_hex_version_1 => 1,
            HostFunction::ext_misc_runtime_version_version_1 => 1,
            HostFunction::ext_allocator_malloc_version_1 => 1,
            HostFunction::ext_allocator_free_version_1 => 1,
            HostFunction::ext_logging_log_version_1 => 3,
            HostFunction::ext_logging_max_level_version_1 => 0,
        }
    }
}
