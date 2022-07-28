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

// TODO: really needs documentation

use crate::chain::chain_information::{ChainInformationFinality, ChainInformationFinalityRef};
use crate::finality;
use crate::finality::justification::verify::{
    verify, Config as VerifyConfig, Error as VerifyError,
};
use crate::header::{self, DigestItemRef, GrandpaAuthority, GrandpaConsensusLogRef};
use crate::informant::HashDisplay;

use alloc::vec::Vec;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    Verify(VerifyError),
    TargetHashMismatch {
        justification_target_hash: [u8; 32],
        justification_target_height: u64,
        header_hash: [u8; 32],
    },
    NonMinimalProof,
    EmptyProof,
    InvalidHeader(header::Error),
    InvalidJustification(finality::justification::decode::Error),
    WrongChainAlgorithm,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Verify(err) => fmt::Display::fmt(err, f),
            Error::TargetHashMismatch {
                justification_target_hash,
                justification_target_height,
                header_hash,
            } => {
                write!(
                    f,
                    "Justification target hash ({}, height: {}) doesn't match the hash of the associated header ({})",
                    HashDisplay(justification_target_hash),
                    justification_target_height,
                    HashDisplay(header_hash)
                )
            }
            Error::NonMinimalProof => write!(
                f,
                "Warp sync proof fragment doesn't contain an authorities list change"
            ),
            Error::EmptyProof => write!(f, "Warp sync proof is empty"),
            Error::InvalidHeader(_) => write!(f, "Failed to decode header"),
            Error::InvalidJustification(_) => write!(f, "Failed to decode justification"),
            Error::WrongChainAlgorithm => {
                write!(f, "Chain information doesn't use the Grandpa algorithm")
            }
        }
    }
}

#[derive(Debug)]
pub struct Verifier {
    /// If `true`, the verification should instantly fail with an error.
    wrong_chain_algorithm: bool,

    index: usize,
    authorities_set_id: u64,
    authorities_list: Vec<GrandpaAuthority>,
    fragments: Vec<WarpSyncFragment>,
    is_proof_complete: bool,

    block_number_bytes: usize,
}

impl Verifier {
    pub fn new(
        start_chain_information_finality: ChainInformationFinalityRef,
        block_number_bytes: usize,
        warp_sync_response_fragments: Vec<WarpSyncFragment>,
        is_proof_complete: bool,
    ) -> Self {
        let (wrong_chain_algorithm, authorities_list, authorities_set_id) =
            match start_chain_information_finality {
                ChainInformationFinalityRef::Grandpa {
                    finalized_triggered_authorities,
                    after_finalized_block_authorities_set_id,
                    ..
                } => {
                    let authorities_list = finalized_triggered_authorities.to_vec();
                    (
                        false,
                        authorities_list,
                        after_finalized_block_authorities_set_id,
                    )
                }
                _ => (true, Vec::new(), 0),
            };

        Self {
            wrong_chain_algorithm,
            index: 0,
            authorities_set_id,
            authorities_list,
            fragments: warp_sync_response_fragments,
            is_proof_complete,
            block_number_bytes,
        }
    }

    pub fn next(mut self) -> Result<Next, Error> {
        if self.wrong_chain_algorithm {
            return Err(Error::WrongChainAlgorithm);
        }

        if self.fragments.is_empty() {
            if self.is_proof_complete {
                return Ok(Next::EmptyProof);
            }
            return Err(Error::EmptyProof);
        }

        debug_assert!(self.fragments.len() > self.index);
        let fragment = &self.fragments[self.index];

        let fragment_header_hash =
            header::hash_from_scale_encoded_header(&fragment.scale_encoded_header);
        let justification = finality::justification::decode::decode_partial_grandpa(
            // TODO: don't use decode_partial but decode
            &fragment.scale_encoded_justification,
            self.block_number_bytes,
        )
        .map_err(Error::InvalidJustification)?
        .0;
        if *justification.target_hash != fragment_header_hash {
            return Err(Error::TargetHashMismatch {
                justification_target_hash: *justification.target_hash,
                justification_target_height: justification.target_number,
                header_hash: fragment_header_hash,
            });
        }

        verify(VerifyConfig {
            justification,
            block_number_bytes: self.block_number_bytes,
            authorities_list: self.authorities_list.iter().map(|a| &a.public_key),
            authorities_set_id: self.authorities_set_id,
        })
        .map_err(Error::Verify)?;

        let authorities_list =
            header::decode(&fragment.scale_encoded_header, self.block_number_bytes)
                .map_err(Error::InvalidHeader)?
                .digest
                .logs()
                .find_map(|log_item| match log_item {
                    DigestItemRef::GrandpaConsensus(grandpa_log_item) => match grandpa_log_item {
                        GrandpaConsensusLogRef::ScheduledChange(change)
                        | GrandpaConsensusLogRef::ForcedChange { change, .. } => {
                            Some(change.next_authorities)
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .map(|next_authorities| next_authorities.map(GrandpaAuthority::from).collect());

        self.index += 1;

        if let Some(authorities_list) = authorities_list {
            self.authorities_list = authorities_list;
            self.authorities_set_id += 1;
        } else if !self.is_proof_complete || self.index != self.fragments.len() {
            return Err(Error::NonMinimalProof);
        }

        if self.index == self.fragments.len() {
            Ok(Next::Success {
                scale_encoded_header: fragment.scale_encoded_header.clone(), // TODO: cloning :-/
                chain_information_finality: ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id: self.authorities_set_id,
                    finalized_triggered_authorities: self.authorities_list,
                    finalized_scheduled_change: None,
                },
            })
        } else {
            Ok(Next::NotFinished(self))
        }
    }
}

pub enum Next {
    NotFinished(Verifier),
    EmptyProof,
    Success {
        scale_encoded_header: Vec<u8>,
        chain_information_finality: ChainInformationFinality,
    },
}

/// Fragment to be verified.
#[derive(Debug)]
pub struct WarpSyncFragment {
    /// Header of a block in the chain.
    pub scale_encoded_header: Vec<u8>,

    /// Justification that proves the finality of [`WarpSyncFragment::scale_encoded_header`].
    pub scale_encoded_justification: Vec<u8>,
}
