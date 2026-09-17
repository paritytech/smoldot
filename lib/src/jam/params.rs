// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Chain-level JAM protocol parameters.

use super::codec::{DecodeError, Decoder};

/// Chain-level constants from the chain specification. Never global.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// E: slots per epoch (`epoch_period` in PolkaJam).
    pub epoch_len: u32,
    /// Upper bound on validator-set sizes: three times `core_count` (GP 0.8.0).
    pub max_validators: u16,
    /// P: seconds per slot (`slot_period_sec` in PolkaJam).
    pub slot_seconds: u32,
    /// Y: first slot outside the ticket submission period.
    pub epoch_tail_start: u32,
    /// K: tickets per block extrinsic (`max_tickets_per_block` in PolkaJam).
    pub max_tickets_per_ext: u16,
    pub deposit_per_item: u64,
    pub deposit_per_byte: u64,
    pub deposit_per_account: u64,
    pub core_count: u16,
    pub min_turnaround_period: u32,
    pub max_accumulate_gas: u64,
    pub max_is_authorized_gas: u64,
    pub max_refine_gas: u64,
    pub block_gas_limit: u64,
    pub recent_block_count: u16,
    pub max_work_items: u16,
    pub max_dependencies: u16,
    pub max_lookup_anchor_age: u32,
    pub auth_window: u16,
    pub auth_queue_len: u16,
    pub rotation_period: u16,
    pub max_extrinsics: u16,
    pub availability_timeout: u16,
    pub max_authorizer_code_size: u32,
    pub max_input: u32,
    pub max_service_code_size: u32,
    pub max_imports: u32,
    pub max_report_elective_data: u32,
    pub transfer_memo_size: u32,
    pub max_exports: u32,
}

impl Params {
    /// GP 0.8.0 Safrole permits independent set sizes in {6, 9, ..., 3C}.
    pub(crate) fn is_valid_validator_count(&self, count: usize) -> bool {
        count >= 6 && count <= usize::from(self.max_validators) && count.is_multiple_of(3)
    }

    /// Decodes PolkaJam's encoded `ProtocolParameters`.
    ///
    /// Fields are fixed-width little-endian integers (not compact integers) in
    /// PolkaJam's declaration order. GP 0.8.0 has 29 fields (122 bytes); other
    /// lengths are rejected. Validator counts are bounded by three times the core
    /// count. This parses the representation, not all protocol consistency
    /// constraints.
    pub fn from_protocol_parameters(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut input = Decoder::new(bytes);
        let deposit_per_item = input.u64()?;
        let deposit_per_byte = input.u64()?;
        let deposit_per_account = input.u64()?;
        let core_count = input.u16()?;
        let min_turnaround_period = input.u32()?;
        let epoch_len = input.u32()?;
        let max_accumulate_gas = input.u64()?;
        let max_is_authorized_gas = input.u64()?;
        let max_refine_gas = input.u64()?;
        let block_gas_limit = input.u64()?;
        let recent_block_count = input.u16()?;
        let max_work_items = input.u16()?;
        let max_dependencies = input.u16()?;
        let max_tickets_per_ext = input.u16()?;
        let max_lookup_anchor_age = input.u32()?;
        let auth_window = input.u16()?;
        let slot_seconds = u32::from(input.u16()?);
        let auth_queue_len = input.u16()?;
        let rotation_period = input.u16()?;
        let max_extrinsics = input.u16()?;
        let availability_timeout = input.u16()?;
        let max_authorizer_code_size = input.u32()?;
        let max_input = input.u32()?;
        let max_service_code_size = input.u32()?;
        let max_imports = input.u32()?;
        let max_report_elective_data = input.u32()?;
        let transfer_memo_size = input.u32()?;
        let max_exports = input.u32()?;
        let epoch_tail_start = input.u32()?;
        input.finish()?;
        // The same core-count and epoch-length limits as PolkaJam. The epoch
        // limit keeps ceil(2E / validator_count) within a one-byte attempt.
        if !(2..=341).contains(&core_count) || epoch_len > 765 {
            return Err(DecodeError::InvalidParameters);
        }
        let max_validators = core_count
            .checked_mul(3)
            .ok_or(DecodeError::InvalidParameters)?;
        Ok(Self {
            epoch_len,
            max_validators,
            slot_seconds,
            epoch_tail_start,
            max_tickets_per_ext,
            deposit_per_item,
            deposit_per_byte,
            deposit_per_account,
            core_count,
            min_turnaround_period,
            max_accumulate_gas,
            max_is_authorized_gas,
            max_refine_gas,
            block_gas_limit,
            recent_block_count,
            max_work_items,
            max_dependencies,
            max_lookup_anchor_age,
            auth_window,
            auth_queue_len,
            rotation_period,
            max_extrinsics,
            availability_timeout,
            max_authorizer_code_size,
            max_input,
            max_service_code_size,
            max_imports,
            max_report_elective_data,
            transfer_memo_size,
            max_exports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jam::test_support::assert_strict;
    use alloc::vec::Vec;

    /// Field `i` holds `i + 1` in `widths[i]` bytes, so swapped fields are caught
    /// even where official defaults agree.
    fn distinct_fields(widths: &[usize]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (index, width) in widths.iter().enumerate() {
            bytes.extend_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes()[..*width]);
        }
        bytes
    }

    const WIDTHS: [usize; 29] = [
        8, 8, 8, 2, 4, 4, 8, 8, 8, 8, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4,
    ];

    #[test]
    fn field_order_widths_and_total_consumption() {
        let bytes = distinct_fields(&WIDTHS);
        assert_eq!(bytes.len(), 122);
        let expected = Params {
            deposit_per_item: 1,
            deposit_per_byte: 2,
            deposit_per_account: 3,
            core_count: 4,
            min_turnaround_period: 5,
            epoch_len: 6,
            max_accumulate_gas: 7,
            max_is_authorized_gas: 8,
            max_refine_gas: 9,
            block_gas_limit: 10,
            recent_block_count: 11,
            max_work_items: 12,
            max_dependencies: 13,
            max_tickets_per_ext: 14,
            max_lookup_anchor_age: 15,
            auth_window: 16,
            slot_seconds: 17,
            auth_queue_len: 18,
            rotation_period: 19,
            max_extrinsics: 20,
            availability_timeout: 21,
            max_authorizer_code_size: 22,
            max_input: 23,
            max_service_code_size: 24,
            max_imports: 25,
            max_report_elective_data: 26,
            transfer_memo_size: 27,
            max_exports: 28,
            epoch_tail_start: 29,
            max_validators: 12,
        };
        assert_eq!(
            assert_strict(&bytes, Params::from_protocol_parameters),
            expected
        );
    }

    #[test]
    fn parameter_shape_bounds() {
        for cores in [0_u16, 1, 2, 341, 342, u16::MAX] {
            for epoch in [0_u32, 765, 766, u32::MAX] {
                let mut bytes = distinct_fields(&WIDTHS);
                bytes[24..26].copy_from_slice(&cores.to_le_bytes());
                bytes[30..34].copy_from_slice(&epoch.to_le_bytes());
                let result = Params::from_protocol_parameters(&bytes);
                if (2..=341).contains(&cores) && epoch <= 765 {
                    assert_eq!(
                        result.unwrap().max_validators,
                        cores.checked_mul(3).unwrap()
                    );
                } else {
                    assert_eq!(result, Err(DecodeError::InvalidParameters));
                }
            }
        }
    }

    #[test]
    fn rejects_gray_paper_0_7_2_parameters() {
        // The 0.7.2 layout also carries N, V, We and Wp.
        let legacy = distinct_fields(&[
            8, 8, 8, 2, 4, 4, 8, 8, 8, 8, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4,
        ]);
        assert_eq!(legacy.len(), 134);
        assert_eq!(
            Params::from_protocol_parameters(&legacy),
            Err(DecodeError::TrailingBytes)
        );
    }
}
