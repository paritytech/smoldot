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

/** A DNS-over-HTTPS resolver. `url` builds the query for a hostname and a record type. */
interface Provider {
    host: string,
    url: (hostname: string, recordType: 'A' | 'AAAA') => string,
}

/**
 * Resolvers, in the order they are started. The first one is queried right away. Each following
 * one is started `PROVIDER_STAGGER_MS` later, or immediately if the previous one has already
 * failed. The first answer wins and the other requests are aborted.
 */
const PROVIDERS: ReadonlyArray<Provider> = [
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

/**
 * Delay after which the next provider is also queried when the previous one hasn't answered yet.
 *
 * Short enough that a slow or unreachable provider doesn't eat up the time budget of the
 * connection attempt, long enough that a healthy provider usually answers before a second
 * request is sent.
 */
const PROVIDER_STAGGER_MS = 500;

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
 * Sends one request to `provider` and returns the first address of the wanted family.
 *
 * Rejects on any failure, with the provider's host prefixed to the reason.
 */
async function queryProvider(
    provider: Provider,
    hostname: string,
    family: 4 | 6,
    signal: AbortSignal,
    fetchImpl: typeof fetch,
): Promise<string> {
    const recordType = family === 4 ? 'A' : 'AAAA';
    try {
        const response = await fetchImpl(provider.url(hostname, recordType), {
            headers: { accept: 'application/dns-json' },
            signal,
        });
        if (!response.ok)
            throw new Error('HTTP status ' + response.status);
        const addresses = parseDnsJsonAnswer(await response.json(), family);
        if (addresses.length === 0)
            throw new Error('no ' + recordType + ' record');
        return addresses[0]!;
    } catch (error) {
        throw new Error(provider.host + ': ' + (error instanceof Error ? error.message : String(error)));
    }
}

/**
 * Races the providers for the addresses of one family.
 *
 * The first provider is queried immediately. Every `staggerMs`, or as soon as the previous
 * request has failed, the next provider is started as well. The first address received is
 * returned and the requests still pending are aborted. Rejects with the last failure once every
 * provider has failed, or with "DNS resolution aborted" as soon as `signal` fires.
 */
function raceProviders(
    hostname: string,
    family: 4 | 6,
    signal: AbortSignal,
    fetchImpl: typeof fetch,
    staggerMs: number,
): Promise<string> {
    return new Promise((resolve, reject) => {
        // Aborting `inner` cancels every request of this race.
        const inner = new AbortController();
        let nextIndex = 0;
        let failed = 0;
        let settled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;

        // The first outcome wins. The race is then over and the pending requests are cancelled.
        function finish() {
            settled = true;
            clearTimeout(timer);
            signal.removeEventListener('abort', onAbort);
            inner.abort();
        }

        function succeed(address: string) {
            if (settled)
                return;
            finish();
            resolve(address);
        }

        function fail(error: Error) {
            if (settled)
                return;
            finish();
            reject(error);
        }

        function onAbort() {
            fail(new Error('DNS resolution aborted'));
        }

        // A request has failed. The next provider is started right away rather than after the
        // stagger, unless every provider has failed by now.
        function onFailure(error: Error) {
            // A request cancelled after the win rejects as well, and must be ignored.
            if (settled)
                return;
            failed += 1;
            if (failed === PROVIDERS.length)
                fail(error);
            else
                startNext();
        }

        // Sends the query to the next provider. Called once at the start, then again either
        // when the stagger timer fires or when a request fails.
        function startNext() {
            const provider = PROVIDERS[nextIndex];
            if (provider === undefined)
                return; // Every provider has been started already.
            nextIndex += 1;
            queryProvider(provider, hostname, family, inner.signal, fetchImpl).then(succeed, onFailure);

            // Arm the timer that starts the provider after this one. If this request answers
            // first, `finish` clears the timer. If it fails first, `onFailure` calls `startNext`
            // directly, and the `clearTimeout` below makes sure the timer doesn't do it again.
            clearTimeout(timer);
            if (nextIndex < PROVIDERS.length)
                timer = setTimeout(startNext, staggerMs);
        }

        // An abort listener never fires for a signal that is already aborted.
        if (signal.aborted) {
            onAbort();
            return;
        }
        signal.addEventListener('abort', onAbort);
        startNext();
    });
}

/**
 * Resolves `hostname` to an IP address over DNS-over-HTTPS.
 *
 * `family` restricts the address family. When it is `undefined`, A records are looked up first
 * and AAAA records only if no A record was found.
 *
 * A hostname that is already an IP literal of an acceptable family is returned as is.
 *
 * `fetchImpl` and `staggerMs` exist so that tests can run without network access and without
 * waiting for the real stagger.
 */
export async function resolveDnsOverHttps(
    hostname: string,
    family: 4 | 6 | undefined,
    signal: AbortSignal,
    fetchImpl: typeof fetch = fetch,
    staggerMs: number = PROVIDER_STAGGER_MS,
): Promise<string> {
    const lowercase = hostname.toLowerCase();
    if (lowercase === 'localhost' || lowercase.endsWith('.localhost'))
        return family === 6 ? '::1' : '127.0.0.1';
    if (family !== 6 && isIpLiteral(hostname, 4))
        return hostname;
    if (family !== 4 && isIpLiteral(hostname, 6))
        return hostname;

    if (family !== undefined)
        return raceProviders(hostname, family, signal, fetchImpl, staggerMs);

    // A records are preferred. AAAA records are only looked up when there is none. If the
    // resolution was aborted meanwhile, the second race rejects right away as well.
    try {
        return await raceProviders(hostname, 4, signal, fetchImpl, staggerMs);
    } catch {
        return raceProviders(hostname, 6, signal, fetchImpl, staggerMs);
    }
}
