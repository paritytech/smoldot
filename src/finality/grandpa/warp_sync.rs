use crate::chain::chain_information::{ChainInformation, ChainInformationFinality};
use crate::finality::justification::verify::{
    verify, Config as VerifyConfig, Error as VerifyError,
};
use crate::header::{DigestItemRef, GrandpaConsensusLogRef};
use crate::network::service::GrandpaWarpSyncResponseFragment;

pub struct Verifier {
    index: usize,
    authorities_list: Vec<[u8; 32]>,
    fragments: Vec<GrandpaWarpSyncResponseFragment>,
}

impl Verifier {
    pub fn new(
        genesis_chain_infomation: &ChainInformation,
        warp_sync_response_fragments: Vec<GrandpaWarpSyncResponseFragment>,
    ) -> Self {
        let authorities_list = match &genesis_chain_infomation.finality {
            ChainInformationFinality::Grandpa {
                finalized_triggered_authorities,
                ..
            } => finalized_triggered_authorities
                .iter()
                .map(|auth| auth.public_key)
                .collect(),
            _ => unimplemented!(),
        };

        Self {
            index: 0,
            authorities_list,
            fragments: warp_sync_response_fragments,
        }
    }

    pub fn next(mut self) -> Result<Next, VerifyError> {
        let authorities_set_id = self.index as u64;
        let fragment = &self.fragments[self.index];

        verify(VerifyConfig {
            justification: (&fragment.justification).into(),
            authorities_list: self.authorities_list.iter(),
            authorities_set_id,
        })?;

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

        if self.index == self.fragments.len() {
            Ok(Next::Success)
        } else {
            Ok(Next::NotFinished(self))
        }
    }
}

pub enum Next {
    NotFinished(Verifier),
    Success,
}
