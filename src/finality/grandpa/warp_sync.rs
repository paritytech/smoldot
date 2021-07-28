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

use crate::chain::chain_information::{ChainInformationFinality, ChainInformationFinalityRef};
use crate::finality::justification::verify::{
    verify, Config as VerifyConfig, Error as VerifyError,
};
use crate::header::{DigestItemRef, GrandpaAuthority, GrandpaConsensusLogRef, Header};
use crate::informant::HashDisplay;
use crate::network::protocol::GrandpaWarpSyncResponseFragment;

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
        }
    }
}

#[derive(Debug)]
pub struct Verifier {
    index: usize,
    authorities_set_id: u64,
    authorities_list: Vec<GrandpaAuthority>,
    fragments: Vec<GrandpaWarpSyncResponseFragment>,
    is_proof_complete: bool,
}

impl Verifier {
    pub fn new(
        start_chain_information_finality: ChainInformationFinalityRef,
        warp_sync_response_fragments: Vec<GrandpaWarpSyncResponseFragment>,
        is_proof_complete: bool,
    ) -> Self {
        let (authorities_list, authorities_set_id) = match start_chain_information_finality {
            ChainInformationFinalityRef::Grandpa {
                finalized_triggered_authorities,
                after_finalized_block_authorities_set_id,
                ..
            } => {
                let authorities_list = finalized_triggered_authorities.iter().cloned().collect();
                (authorities_list, after_finalized_block_authorities_set_id)
            }
            // TODO:
            _ => unimplemented!(),
        };

        Self {
            index: 0,
            authorities_set_id,
            authorities_list,
            fragments: warp_sync_response_fragments,
            is_proof_complete,
        }
    }

    pub fn next(mut self) -> Result<Next, Error> {
        if self.fragments.is_empty() {
            return Err(Error::EmptyProof);
        }

        debug_assert!(self.fragments.len() > self.index);
        let fragment = &self.fragments[self.index];

        let fragment_header_hash = fragment.header.hash();
        if fragment.justification.target_hash != fragment_header_hash {
            return Err(Error::TargetHashMismatch {
                justification_target_hash: fragment.justification.target_hash,
                justification_target_height: fragment.justification.target_number.into(), // TODO: some u32/u64 mismatch here; figure out
                header_hash: fragment_header_hash,
            });
        }

        verify(VerifyConfig {
            justification: (&fragment.justification).into(),
            authorities_list: self.authorities_list.iter().map(|a| &a.public_key),
            authorities_set_id: self.authorities_set_id,
        })
        .map_err(Error::Verify)?;

        let authorities_list = fragment
            .header
            .digest
            .logs()
            .filter_map(|log_item| match log_item {
                DigestItemRef::GrandpaConsensus(grandpa_log_item) => match grandpa_log_item {
                    GrandpaConsensusLogRef::ScheduledChange(change)
                    | GrandpaConsensusLogRef::ForcedChange { change, .. } => {
                        Some(change.next_authorities)
                    }
                    _ => None,
                },
                _ => None,
            })
            .next()
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
                header: fragment.header.clone(),
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
    Success {
        header: Header,
        chain_information_finality: ChainInformationFinality,
    },
}
