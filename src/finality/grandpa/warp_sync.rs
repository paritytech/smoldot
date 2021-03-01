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
use crate::header::{DigestItemRef, GrandpaConsensusLogRef, Header};
use crate::network::protocol::GrandpaWarpSyncResponseFragment;

use alloc::vec::Vec;

#[derive(Debug, derive_more::Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    Verify(VerifyError),
    #[display(fmt = "Justification target hash doesn't match the hash of the associated header.")]
    TargetHashMismatch,
}

#[derive(Debug)]
pub struct Verifier {
    index: usize,
    authorities_set_id: u64,
    authorities_list: Vec<[u8; 32]>,
    fragments: Vec<GrandpaWarpSyncResponseFragment>,
}

impl Verifier {
    pub fn new(
        start_chain_information_finality: ChainInformationFinalityRef,
        warp_sync_response_fragments: Vec<GrandpaWarpSyncResponseFragment>,
    ) -> Self {
        let (authorities_list, authorities_set_id) = match start_chain_information_finality {
            ChainInformationFinalityRef::Grandpa {
                finalized_triggered_authorities,
                after_finalized_block_authorities_set_id,
                ..
            } => {
                let authorities_list = finalized_triggered_authorities
                    .iter()
                    .map(|auth| auth.public_key)
                    .collect();

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
        }
    }

    pub fn next(mut self) -> Result<Next, Error> {
        let fragment = &self.fragments[self.index];

        if fragment.justification.target_hash != fragment.header.hash() {
            return Err(Error::TargetHashMismatch);
        }

        verify(VerifyConfig {
            justification: (&fragment.justification).into(),
            authorities_list: self.authorities_list.iter(),
            authorities_set_id: self.authorities_set_id,
        })
        .map_err(Error::Verify)?;

        self.authorities_list = fragment
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
            .flat_map(|next_authorities| next_authorities)
            .map(|authority| *authority.public_key)
            .collect();

        self.index += 1;
        self.authorities_set_id += 1;

        if self.index == self.fragments.len() {
            Ok(Next::Success {
                header: fragment.header.clone(),
                chain_information_finality: ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id: self.authorities_set_id,
                    finalized_triggered_authorities: {
                        fragment
                            .header
                            .digest
                            .logs()
                            .filter_map(|log_item| match log_item {
                                DigestItemRef::GrandpaConsensus(grandpa_log_item) => {
                                    match grandpa_log_item {
                                        GrandpaConsensusLogRef::ScheduledChange(change)
                                        | GrandpaConsensusLogRef::ForcedChange { change, .. } => {
                                            Some(change.next_authorities)
                                        }
                                        _ => None,
                                    }
                                }
                                _ => None,
                            })
                            .flat_map(|next_authorities| next_authorities)
                            .map(|authority_ref| authority_ref.into())
                            .collect()
                    },
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
