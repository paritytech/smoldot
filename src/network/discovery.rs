// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mechanisms related to discovering nodes that are part of a certain overlay network.
//!
//! # Synopsis
//!
//! Internet is a network of computers. The list of machines that are running a Substrate/Polkadot
//! client is a subset of the Internet. This module provides the mechanisms that help finding out
//! which machines (more precisely, which IP address and port) run a Substrate/Polkadot client.
//!
//! # Details
//!
//! Substrate-compatible chains use two discovery mechanisms:
//!
//! - **Kademlia**. All nodes that belong to a certain chain are encouraged to participate in the
//! Kademlia [DHT](https://en.wikipedia.org/wiki/Distributed_hash_table) of that chain, making it
//! possible to ask a node for the nodes it has learned about in the past.
//! - **mDNS**. By broadcasting UDP packets over the local network, one can find other nodes
//! running the same chain. // TODO: not implemented yet
//!
//! The main discovery mechanism is the DHT. In order to bootstrap this mechanism, a list of nodes
//! known to always be part of the chain is hardcoded in the chain specifications. These nodes are
//! called **boostrap nodes**.
//!
