// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Chain-level JAM protocol parameters.

use super::codec::{DecodeError, Decoder};

/// Chain-level constants from the chain specification. Never global.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// E: slots per epoch (`epoch_period` in PolkaJam).
    pub epoch_len: u32,
    /// V: maximum validator count (`max_val_count` in PolkaJam).
    pub max_validators: u16,
    /// N: attempts per validator (`tickets_attempts_number` in PolkaJam).
    pub ticket_entries: u8,
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
    pub basic_piece_len: u32,
    pub max_imports: u32,
    pub segment_piece_count: u32,
    pub max_report_elective_data: u32,
    pub transfer_memo_size: u32,
    pub max_exports: u32,
}

impl Params {
    /// Decodes PolkaJam's encoded `ProtocolParameters`.
    ///
    /// Fields follow `jam-types/src/simple.rs::ProtocolParameters` in declaration
    /// order, using fixed-width little-endian integers (not compact integers).
    /// The six contract fields retain their JAM names above. The on-wire `u16`
    /// attempt count must fit in `ticket_entries`; trailing bytes are rejected.
    /// This parses the representation, not all protocol consistency constraints.
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
        let ticket_entries =
            u8::try_from(input.u16()?).map_err(|_| DecodeError::InvalidParameters)?;
        let auth_window = input.u16()?;
        let slot_seconds = u32::from(input.u16()?);
        let auth_queue_len = input.u16()?;
        let rotation_period = input.u16()?;
        let max_extrinsics = input.u16()?;
        let availability_timeout = input.u16()?;
        let max_validators = input.u16()?;
        let max_authorizer_code_size = input.u32()?;
        let max_input = input.u32()?;
        let max_service_code_size = input.u32()?;
        let basic_piece_len = input.u32()?;
        let max_imports = input.u32()?;
        let segment_piece_count = input.u32()?;
        let max_report_elective_data = input.u32()?;
        let transfer_memo_size = input.u32()?;
        let max_exports = input.u32()?;
        let epoch_tail_start = input.u32()?;
        input.finish()?;
        Ok(Self {
            epoch_len,
            max_validators,
            ticket_entries,
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
            basic_piece_len,
            max_imports,
            segment_piece_count,
            max_report_elective_data,
            transfer_memo_size,
            max_exports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn field_order_widths_and_total_consumption() {
        // Distinct values catch swapped fields even when official defaults agree.
        let widths = [
            8, 8, 8, 2, 4, 4, 8, 8, 8, 8, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4,
        ];
        let mut bytes = Vec::new();
        for (index, width) in widths.into_iter().enumerate() {
            bytes.extend_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes()[..width]);
        }
        assert_eq!(bytes.len(), 134);
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
            ticket_entries: 16,
            auth_window: 17,
            slot_seconds: 18,
            auth_queue_len: 19,
            rotation_period: 20,
            max_extrinsics: 21,
            availability_timeout: 22,
            max_validators: 23,
            max_authorizer_code_size: 24,
            max_input: 25,
            max_service_code_size: 26,
            basic_piece_len: 27,
            max_imports: 28,
            segment_piece_count: 29,
            max_report_elective_data: 30,
            transfer_memo_size: 31,
            max_exports: 32,
            epoch_tail_start: 33,
        };
        assert_eq!(Params::from_protocol_parameters(&bytes), Ok(expected));
        for end in 0..bytes.len() {
            assert!(Params::from_protocol_parameters(&bytes[..end]).is_err());
        }
        bytes.push(0);
        assert_eq!(
            Params::from_protocol_parameters(&bytes),
            Err(DecodeError::TrailingBytes)
        );
        bytes.pop();
        bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[24..26].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[30..34].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[78..80].copy_from_slice(&255_u16.to_le_bytes());
        let decoded = Params::from_protocol_parameters(&bytes).unwrap();
        assert_eq!(decoded.deposit_per_item, u64::MAX);
        assert_eq!(decoded.core_count, u16::MAX);
        assert_eq!(decoded.epoch_len, u32::MAX);
        assert_eq!(decoded.ticket_entries, 255);
        bytes[78..80].copy_from_slice(&256_u16.to_le_bytes());
        assert_eq!(
            Params::from_protocol_parameters(&bytes),
            Err(DecodeError::InvalidParameters)
        );
    }
}
