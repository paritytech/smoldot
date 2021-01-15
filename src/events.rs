// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Events retrieval and decoding.
//!
//! # Overview
//!
//! While this behaviour is not part of the specifications and is thus not a strict requirement,
//! Substrate-compatible blockchains built using the Substrate framework provide a storage item
//! (in other words, an entry in the storage, with a specific key) containing a list of so-called
//! *events*. This storage item is updated at each block with the events that have happened in
//! the latest block.
//!
//! > **Note**: Events include, for example, a transfer between two accounts, a change in the
//! >           validators nominated by a nominator, the beginning of a referundum, etc.
//!
//! This module provides the tooling necessary to help retrieve and decode said events.
//!
//! In order to determine which storage key holds the list of events, and in order to decode
//! this list of events, one needs to provide the *metadata*. See the [metadata](crate::metadata)
//! module for information about what the metadata is and how to obtain it.
//!
//! # Usage
//!
//! In order to know the events that have happened during a specific block:
//!
//! - Obtain the *metadata* of the runtime used by the desired block. This is out of scope of this
//! module. See the [metadata](crate::metadata) module for more information.
//! - Call [`events_storage_key`] in order to obtain a key where to find the list of events in the
//! storage. If [`events_storage_key`] returns an error, the runtime most likely doesn't support
//! events.
//! - Obtain the storage value corresponding to the key obtained at the previous step. This is out
//! of scope of this module. If there is no storage value at this key, this most likely indicates
//! a bug somewhere, either in substrate-lite or in the runtime.
//! - Call [`decode_events`], passing the storage value. An error is returned if there exists an
//! incompatibility between substrate-lite and this runtime. See the next section.
//!
//! # Flaw in the design
//!
//! In the SCALE codec, each field is put one behind the other in an unstructured way. The start
//! of a new field is known by adding the length of all the preceding fields, and the length of
//! a field depends on the type of data it contains. The type of data is not explicitly laid out
//! and is only known through context.
//!
//! The list of events (encoded using SCALE) contains, amongst other things, the values of the
//! parameters of said event. In order to be able decode this list of events, one has to know the
//! types of these parameter values. This information is found in the metadata, in the form of a
//! string representing the type as written out in the original Rust source code. This type could
//! be anything, from a primitive type (e.g. `u32`) to a type alias (`type Foo = ...;`), or a
//! locally-defined struct.
//!
//! For this module to function properly, it has to parse these strings representing Rust types
//! and hard-code a list of types known to be used in the runtime code. This ranges from `u32` to
//! for example `EthereumAddress`.
//!
//! Runtime upgrades can introduce new types and (albeit unlikely) modify the definition of
//! existing types. As such, the code in this module can stop working after any runtime upgrade.
//! From the point of view of substrate-lite, however, there is simply no way to prevent this
//! from happening.
//!
//! Additionally, the types hard-coded in this module cannot cover the situation of a person
//! creating their custom blockchain and trying to run it with substrate-lite. The code in this
//! module cannot fulfill substrate-lite's promise of being compatible with most Substrate
//! chains.
//!

use crate::metadata::decode as metadata;
use core::{convert::TryFrom, hash::Hasher as _};

/// Returns the key in the storage at which events can be found.
///
/// > **Note**: This key is based entirely on the metadata passed as parameter. Be aware that,
/// >           albeit unlikely, if the metadata changes, the key might change as well.
///
/// An error is returned if the metadata doesn't indicate any storage entry for events, or if the
/// type of the content of the storage entry isn't recognized.
pub fn events_storage_key(mut metadata: metadata::MetadataRef) -> Result<[u8; 32], ()> {
    let module = metadata.modules.find(|m| m.name == "System").ok_or(())?;

    let mut storage = module.storage.ok_or(())?;

    let entry = storage.entries.find(|e| e.name == "Events").ok_or(())?;
    if entry.ty != metadata::StorageEntryTypeRef::Plain("Vec<EventRecord<T::Event, T::Hash>>") {
        return Err(());
    }

    let mut out = [0; 32];
    twox_128(
        storage.prefix.as_bytes(),
        TryFrom::try_from(&mut out[..16]).unwrap(),
    );
    twox_128(
        entry.name.as_bytes(),
        TryFrom::try_from(&mut out[16..]).unwrap(),
    );
    Ok(out)
}

/// Decodes the value of the storage containing the list of events.
// TODO: Vec :-/
pub fn decode_events<'a>(
    metadata: metadata::MetadataRef<'a>,
    storage_value: &'a [u8],
) -> Result<Vec<Event<'a>>, DecodeEventsError<'a>> {
    // The value is a SCALE-encoded `Vec<EventRecord>`. See the definition of `EventRecord`
    // [here](https://github.com/paritytech/substrate/blob/332399d16668a6c769f1a7db154bb9ea3b50e61c/frame%2Fsystem%2Fsrc%2Flib.rs#L285-L295).
    nom::combinator::all_consuming(nom::combinator::flat_map(
        crate::util::nom_scale_compact_usize,
        |num_elems| nom::multi::many_m_n(num_elems, num_elems, event(metadata)),
    ))(storage_value)
    .map(|(_, parse_result)| parse_result)
    .map_err(DecodeEventsError)
}

/// Error potentially returned by [`decode_events`].
#[derive(Debug, derive_more::Display)]
pub struct DecodeEventsError<'a>(nom::Err<nom::error::Error<&'a [u8]>>);

#[derive(Debug)]
pub struct Event<'a> {
    pub phase: Phase,
    pub module_name: &'a str,
    pub event_name: &'a str,
    // TODO: Vec :-/
    pub arguments: Vec<EventArgument>,
    // TODO: Vec :-/
    pub topics: Vec<[u8; 32]>,
}

/// Phase of the block construction during which the event happened.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Event happened during application of the Nth extrinsic.
    ApplyExtrinsic(u32),
    /// Event happened during block finalization.
    Finalization,
    /// Event happened during block initialization.
    Initialization,
}

#[derive(Debug)]
pub enum EventArgument {
    PhantomData,
    Bool(bool),
    U8(u8),
    U32(u32),
    AccountIndex(u32),
    SessionIndex(u32),
    PropIndex(u32),
    ProposalIndex(u32),
    // TODO: varies depending on the chain
    AuthorityIndex(u32),
    AuthorityWeight(u64),
    MemberCount(u32),
    AuthorityId([u8; 32]),
    AccountId([u8; 32]),
    // TODO: varies depending on the chain
    BlockNumber(u32),
    Hash([u8; 32]),
    VoteThreshold(u8),
    Kind([u8; 16]),
    ReferendumIndex(u32),
    DispatchInfo {
        weight: u64,
        class: DispatchClass,
        pays_fee: bool,
    },
    // TODO: varies depending on the chain
    Balance(u128),
    EthereumAddress([u8; 20]),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DispatchClass {
    Normal,
    Operational,
    Mandatory,
}

/// Nom combinator that decodes a SCALE-encoded [`Event`].
fn event<'a, E: nom::error::ParseError<&'a [u8]>>(
    metadata: metadata::MetadataRef<'a>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], Event<'a>, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            phase,
            event_body(metadata),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
                        *<&[u8; 32]>::try_from(b).unwrap()
                    }),
                )
            }),
        )),
        |(phase, (module_name, event_name, arguments), topics)| {
            Event {
                phase,
                module_name,
                event_name,
                arguments,
                topics,
            }
        },
    )
}

/// Nom combinator that decodes a SCALE-encoded [`Phase`].
fn phase<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], Phase, E> {
    nom::branch::alt((
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag(&[0]),
                nom::number::complete::le_u32,
            ),
            Phase::ApplyExtrinsic,
        ),
        nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| Phase::Finalization),
        nom::combinator::map(nom::bytes::complete::tag(&[2]), |_| Phase::Initialization),
    ))(bytes)
}

fn event_body<'a, E: nom::error::ParseError<&'a [u8]>>(
    metadata: metadata::MetadataRef<'a>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], (&'a str, &'a str, Vec<EventArgument>), E> {
    nom::combinator::flat_map(
        nom::combinator::map_opt(
            // Each event argument starts with a module index and an event index.
            nom::sequence::tuple((nom::number::complete::u8, nom::number::complete::u8)),
            move |(module_index, event_index)| {
                // The module index refers to the index of the module, ignoring modules that don't
                // have events.
                let module = metadata
                    .modules
                    .clone()
                    .filter(|m| m.event.is_some())
                    .nth(module_index.into())?;
                // The event index refers to the index within that specific module.
                let event = module.event.unwrap().nth(event_index.into())?;
                Some((module.name, event))
            },
        ),
        move |(module_name, event)| {
            move |mut bytes| {
                let mut arguments = Vec::with_capacity(event.arguments.len());
                for argument in event.arguments {
                    // The way the argument is encoded and its meaning depend on the type encoded
                    // *as a string* in the metadata. This string is the type as written in the
                    // Rust runtime source code. This is really crappy to say the least. It isn't
                    // even possible to know the length in bytes of an encoded argument whose type
                    // is unrecognized. In other words, if we don't support any of the types used
                    // for any of the arguments, the entire list of events becomes unparsable.
                    let (new_bytes, arg_value) = event_argument(argument, bytes)?;
                    bytes = new_bytes;
                    arguments.push(arg_value);
                }

                Ok((bytes, (module_name, event.name, arguments)))
            }
        },
    )
}

fn event_argument<'a, E: nom::error::ParseError<&'a [u8]>>(
    ty: &str,
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], EventArgument, E> {
    // TODO: Vec, Option, tuple
    match ty {
        "PhantomData" => nom::combinator::map(nom::bytes::complete::take(0u32), |_| {
            EventArgument::PhantomData
        })(bytes),
        "DispatchInfo" => nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                nom::branch::alt((
                    nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                        DispatchClass::Normal
                    }),
                    nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                        DispatchClass::Operational
                    }),
                    nom::combinator::map(nom::bytes::complete::tag(&[2]), |_| {
                        DispatchClass::Mandatory
                    }),
                )),
                nom::branch::alt((
                    // Note: this is not a mistake. `0` is `true` and `1` is `false`.
                    nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| true),
                    nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| false),
                )),
            )),
            |(weight, class, pays_fee)| EventArgument::DispatchInfo {
                weight,
                class,
                pays_fee,
            },
        )(bytes),
        "bool" => nom::branch::alt((
            nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                EventArgument::Bool(false)
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                EventArgument::Bool(true)
            }),
        ))(bytes),
        "ReferendumIndex" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::U32)(bytes)
        }
        "Kind" => nom::combinator::map(nom::bytes::complete::take(16u32), |b| {
            EventArgument::Kind(TryFrom::try_from(b).unwrap())
        })(bytes),
        "AuthorityId" => nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
            EventArgument::AuthorityId(TryFrom::try_from(b).unwrap())
        })(bytes),
        "u8" => nom::combinator::map(nom::number::complete::u8, EventArgument::U8)(bytes),
        "u32" => nom::combinator::map(nom::number::complete::le_u32, EventArgument::U32)(bytes),
        "AccountIndex" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::AccountIndex)(bytes)
        }
        "SessionIndex" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::SessionIndex)(bytes)
        }
        "PropIndex" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::PropIndex)(bytes)
        }
        "ProposalIndex" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::ProposalIndex)(bytes)
        }
        "AuthorityIndex" => nom::combinator::map(
            nom::number::complete::le_u32,
            EventArgument::AuthorityIndex,
        )(bytes),
        "AuthorityWeight" => nom::combinator::map(
            nom::number::complete::le_u64,
            EventArgument::AuthorityWeight,
        )(bytes),
        "MemberCount" => {
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::MemberCount)(bytes)
        }
        "AccountId" => nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
            EventArgument::AccountId(TryFrom::try_from(b).unwrap())
        })(bytes),
        "BlockNumber" => {
            // TODO: might vary depending on the chain!
            nom::combinator::map(nom::number::complete::le_u32, EventArgument::BlockNumber)(bytes)
        }
        "Hash" => nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
            EventArgument::Hash(TryFrom::try_from(b).unwrap())
        })(bytes),
        "VoteThreshold" => {
            nom::combinator::map(nom::number::complete::u8, EventArgument::VoteThreshold)(bytes)
        }
        "Balance" => {
            nom::combinator::map(nom::number::complete::le_u128, EventArgument::Balance)(bytes)
        }
        "EthereumAddress" => nom::combinator::map(nom::bytes::complete::take(20u32), |b| {
            EventArgument::EthereumAddress(TryFrom::try_from(b).unwrap())
        })(bytes),
        _v => todo!("{}", _v), // TODO: remove this
    }
}

/// Fills `dest` with the XXHash of `data`.
fn twox_128(data: &[u8], dest: &mut [u8; 16]) {
    let mut h0 = twox_hash::XxHash::with_seed(0);
    let mut h1 = twox_hash::XxHash::with_seed(1);
    h0.write(&data);
    h1.write(&data);
    let r0 = h0.finish();
    let r1 = h1.finish();

    dest[..8].copy_from_slice(&r0.to_le_bytes()[..]);
    dest[8..].copy_from_slice(&r1.to_le_bytes()[..]);
}
