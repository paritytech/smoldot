// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

// DNS resolution for WebRTC multiaddresses in browsers.
//
// Opening a WebRTC connection requires the literal IP address of the remote: it is written in
// the SDP session description handed to the browser. Browsers expose no DNS API, so a
// `/dns/<host>/udp/<port>/webrtc-direct/...` multiaddress is resolved here, over the JSON
// flavour of DNS-over-HTTPS served by Cloudflare and Google.

/**
 * Resolvers queried in order. Every provider is tried for a record type before moving on to the
 * next record type.
 */
const PROVIDERS: ReadonlyArray<{
    host: string,
    url: (hostname: string, recordType: 'A' | 'AAAA') => string,
}> = [
    {
        host: 'cloudflare-dns.com',
        url: (hostname, recordType) =>
            'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(hostname) + '&type=' + recordType,
    },
    {
        host: 'dns.google',
        url: (hostname, recordType) =>
            'https://dns.google/resolve?name=' + encodeURIComponent(hostname) + '&type=' + recordType,
    },
];

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function isIpLiteral(value: string, family: 4 | 6): boolean {
    return family === 4 ? IPV4_REGEX.test(value) : value.includes(':');
}

/**
 * Extracts the addresses of the given family out of the body of a DNS JSON API response.
 *
 * Cloudflare and Google both answer `{ Status, Answer: [{ name, type, TTL, data }] }`. Only
 * records of the wanted type (`1` for A, `28` for AAAA) whose `data` is an address of that
 * family are kept. CNAME records (type `5`) and anything malformed are skipped. Any input that
 * isn't a successful answer yields an empty array.
 */
export function parseDnsJsonAnswer(body: unknown, family: 4 | 6): string[] {
    if (typeof body !== 'object' || body === null)
        return [];
    const { Status, Answer } = body as { Status?: unknown, Answer?: unknown };
    if (Status !== 0 || !Array.isArray(Answer))
        return [];

    const wantedType = family === 4 ? 1 : 28;
    const addresses: string[] = [];
    for (const record of Answer) {
        if (typeof record !== 'object' || record === null)
            continue;
        const { type, data } = record as { type?: unknown, data?: unknown };
        if (type === wantedType && typeof data === 'string' && isIpLiteral(data, family))
            addresses.push(data);
    }
    return addresses;
}

/**
 * Resolves `hostname` to an IP address over DNS-over-HTTPS.
 *
 * `family` restricts the address family.
 * Providers are tried in order for each record
 * type, and the first address found is returned.
 *
 * A hostname that is already an IP literal of an acceptable family is
 * returned as is.
 *
 * `fetchImpl` exists so that tests can run without network access.
 */
export async function resolveDnsOverHttps(
    hostname: string,
    family: 4 | 6 | undefined,
    signal: AbortSignal,
    fetchImpl: typeof fetch = fetch,
): Promise<string> {
    const families: Array<4 | 6> = family === undefined ? [4, 6] : [family];

    const lowercase = hostname.toLowerCase();
    if (lowercase === 'localhost' || lowercase.endsWith('.localhost'))
        return families[0] === 4 ? '127.0.0.1' : '::1';
    for (const candidate of families) {
        if (isIpLiteral(hostname, candidate))
            return hostname;
    }

    let lastError = new Error('no DNS-over-HTTPS provider available');
    for (const candidate of families) {
        const recordType = candidate === 4 ? 'A' : 'AAAA';
        for (const provider of PROVIDERS) {
            if (signal.aborted)
                throw new Error('DNS resolution aborted');
            try {
                const response = await fetchImpl(provider.url(hostname, recordType), {
                    headers: { accept: 'application/dns-json' },
                    signal,
                });
                if (!response.ok)
                    throw new Error('HTTP status ' + response.status);
                const addresses = parseDnsJsonAnswer(await response.json(), candidate);
                if (addresses.length === 0)
                    throw new Error('no ' + recordType + ' record');
                return addresses[0]!;
            } catch (error) {
                lastError = new Error(
                    provider.host + ': ' + (error instanceof Error ? error.message : String(error))
                );
            }
        }
    }
    throw lastError;
}
