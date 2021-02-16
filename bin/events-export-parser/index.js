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

// TODO: reference https://github.com/polkadot-js/api/blob/a9c9fb5769dec7ada8612d6068cf69de04aa15ed/packages/types/src/interfaces/system/EventRecord.spec.ts

// Note: at the time of writing of this comment, this script must be run
// with `node --experimental-json-modules` due to the `@polkadot/types`
// dependency doing weird things.

import { default as sqlite } from 'better-sqlite3';
import { TypeRegistry } from '@polkadot/types';
import { Metadata } from '@polkadot/metadata';

let args = process.argv.slice(2);

let db_connection = sqlite(args[0], {});

const block_events_query = db_connection.prepare('SELECT events_storage, runtime_version FROM events WHERE block_height = ?');
const metadata_query = db_connection.prepare('SELECT metadata FROM metadata WHERE runtime_version = ?');

var block_height = 0;
var current_runtime_version = null;
var registry = new TypeRegistry();

while (true) {
    block_height += 1;
    const row = block_events_query.get(block_height);
    if (!row) {
        console.info("Block #" + block_height + " not found in events database. Stopping.")
        break;
    }

    if (row.runtime_version != current_runtime_version) {
        current_runtime_version = row.runtime_version;

        const undecoded_metadata = metadata_query.get(row.runtime_version).metadata;
        const metadata = new Metadata(registry, undecoded_metadata);
        registry.setMetadata(metadata);
    }

    const event_records = registry.createType('Vec<EventRecord>', row.events_storage, true);

    event_records.forEach((record) => {
        const data = record.event.data.toString();
        if (data.search("5") != -1) {  // TODO: address
            console.log(data, record.event.section, record.event.method);
        }
    })
}
