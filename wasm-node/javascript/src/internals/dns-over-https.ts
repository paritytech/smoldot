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
// `/dns/<host>/udp/<port>/webrtc-direct/...` multiaddress is resolved here, over DNS-over-HTTPS
// as specified by RFC 8484.

/** A DNS-over-HTTPS resolver. `url` is the endpoint the `dns` parameter is appended to. */
interface Provider {
    host: string,
    url: string,
}

/**
 * Resolvers, in the order they are started. The first one is queried right away. Each following
 * one is started `PROVIDER_STAGGER_MS` later, or immediately if the previous one has already
 * failed. The first answer wins and the other requests are aborted.
 */
const PROVIDERS: ReadonlyArray<Provider> = [
    { host: 'cloudflare-dns.com', url: 'https://cloudflare-dns.com/dns-query' },
    { host: 'dns.quad9.net', url: 'https://dns.quad9.net/dns-query' },
    { host: 'doh.dns.sb', url: 'https://doh.dns.sb/dns-query' },
    { host: 'dns.google', url: 'https://dns.google/dns-query' },
];

/**
 * Delay after which the next provider is also queried when the previous one hasn't answered yet.
 *
 * A warm answer from a healthy provider takes a few tens of milliseconds and arrives well before
 * this delay, so only one provider is normally asked. A cold lookup or a slow mobile link may
 * exceed it, which merely costs one redundant request that is aborted as soon as the first
 * answer arrives.
 */
const PROVIDER_STAGGER_MS = 250;

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function isIpLiteral(value: string, family: 4 | 6): boolean {
    return family === 4 ? IPV4_REGEX.test(value) : value.includes(':');
}

/**
 * Builds the query asking for the addresses of `hostname` of the given family, base64url-encoded
 * as the `dns` parameter of the request carries it. The identifier is `0`, as RFC 8484
 * recommends for GET requests so that HTTP caches can serve identical queries.
 *
 * Throws if `hostname` isn't a valid DNS name: every label must be 1 to 63 bytes of printable
 * ASCII, and the whole name at most 253. A trailing dot is accepted.
 */
export function encodeDnsQuery(hostname: string, family: 4 | 6): string {
    const name = hostname.replace(/\.$/, '');
    const labels = name.split('.');
    if (name.length > 253 || !labels.every((label) => /^[!-~]{1,63}$/.test(label)))
        throw new Error('invalid hostname');

    const header = String.fromCharCode(
        0, 0,             // Identifier.
        1, 0,             // Flags: recursion desired.
        0, 1,             // One question.
        0, 0, 0, 0, 0, 0, // No answer, authority or additional record.
    );
    const question = labels.map((label) => String.fromCharCode(label.length) + label).join('')
        + String.fromCharCode(0, 0, family === 4 ? 1 : 28, 0, 1); // Root label, QTYPE, QCLASS IN.
    return btoa(header + question).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Textual form of a 16-byte IPv6 address, with the first run of zero groups collapsed. */
function formatIpv6(bytes: Uint8Array): string {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2)
        groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
    return groups.join(':').replace(/(^|:)(0:)+0(:|$)/, '::');
}

/**
 * Extracts the addresses of the given family out of a DNS response message.
 *
 * Only the answer section is looked at, and only its records of the wanted type (A for IPv4,
 * AAAA for IPv6) whose data has the size of an address are kept, in the order they appear.
 *
 * Throws if the message isn't a well-formed response.
 */
export function parseDnsMessageAnswer(message: Uint8Array, family: 4 | 6): string[] {
    // Cursor over the message. Every read throws when it would run past the end.
    let position = 0;
    const malformed = () => new Error('malformed answer');
    const take = (length: number): Uint8Array => {
        if (position + length > message.length)
            throw malformed();
        position += length;
        return message.subarray(position - length, position);
    };
    const u8 = (): number => take(1)[0]!;
    const u16 = (): number => (u8() << 8) | u8();
    // A name is a sequence of length-prefixed labels ended by the empty root label, or cut
    // short by a two-byte compression pointer.
    const skipName = (): void => {
        for (let length = u8(); length !== 0; length = u8()) {
            if (length >= 0xc0) {
                u8(); // Second byte of the pointer.
                return;
            }
            if (length >= 0x40)
                throw malformed(); // Reserved label types.
            take(length);
        }
    };

    take(2); // Identifier.
    const flags = u16();
    if ((flags & 0x8000) === 0 || (flags & 0x0200) !== 0)
        throw malformed(); // Not a response, or truncated.
    if ((flags & 0x000f) !== 0)
        return []; // Error code.
    const questions = u16();
    const answers = u16();
    take(4); // NSCOUNT and ARCOUNT.

    for (let i = 0; i < questions; i++) {
        skipName();
        take(4); // QTYPE and QCLASS.
    }

    const wantedType = family === 4 ? 1 : 28;
    const wantedLength = family === 4 ? 4 : 16;
    const addresses: string[] = [];
    for (let i = 0; i < answers; i++) {
        skipName();
        const type = u16();
        take(6); // CLASS and TTL.
        const data = take(u16());
        if (type === wantedType && data.length === wantedLength)
            addresses.push(family === 4 ? data.join('.') : formatIpv6(data));
    }
    return addresses;
}

/**
 * Sends the query to `provider` and returns the first address of the wanted family it answers.
 *
 * Rejects on any failure, with the provider's host prefixed to the reason.
 */
async function queryProvider(
    provider: Provider,
    query: string,
    family: 4 | 6,
    signal: AbortSignal,
    fetchImpl: typeof fetch,
): Promise<string> {
    try {
        const response = await fetchImpl(provider.url + '?dns=' + query, {
            headers: { accept: 'application/dns-message' },
            signal,
        });
        if (!response.ok)
            throw new Error('HTTP status ' + response.status);
        const addresses = parseDnsMessageAnswer(new Uint8Array(await response.arrayBuffer()), family);
        if (addresses.length === 0)
            throw new Error('no ' + (family === 4 ? 'A' : 'AAAA') + ' record');
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
 * provider has failed, with "DNS resolution aborted" as soon as `signal` fires, or right away if
 * `hostname` isn't a valid DNS name.
 */
function raceProviders(
    hostname: string,
    family: 4 | 6,
    signal: AbortSignal,
    fetchImpl: typeof fetch,
    staggerMs: number,
): Promise<string> {
    return new Promise((resolve, reject) => {
        const query = encodeDnsQuery(hostname, family);

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

        // Sends the query to the next provider. Called once at the start, then again either
        // when the stagger timer fires or when a request fails. A failure starts the next
        // provider right away rather than after the stagger, unless every provider has failed.
        function startNext() {
            clearTimeout(timer);
            const provider = PROVIDERS[nextIndex++];
            if (provider === undefined)
                return; // Every provider has been started already.
            if (nextIndex < PROVIDERS.length)
                timer = setTimeout(startNext, staggerMs);
            queryProvider(provider, query, family, inner.signal, fetchImpl).then(succeed, (error: Error) => {
                // A request cancelled after the win rejects as well, and must be ignored.
                if (settled)
                    return;
                if (++failed === PROVIDERS.length)
                    fail(error);
                else
                    startNext();
            });
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
 * A hostname that is already an IP literal of an acceptable family is returned as is. A hostname
 * that isn't a valid DNS name is rejected without any request.
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
