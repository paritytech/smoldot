/**
 * Builds the query asking for the addresses of `hostname` of the given family, base64url-encoded
 * as the `dns` parameter of the request carries it. The identifier is `0`, as RFC 8484
 * recommends for GET requests so that HTTP caches can serve identical queries.
 *
 * Throws if `hostname` isn't a valid DNS name: every label must be 1 to 63 bytes of printable
 * ASCII, and the whole name at most 253. A trailing dot is accepted.
 */
export declare function encodeDnsQuery(hostname: string, family: 4 | 6): string;
/**
 * Extracts the addresses of the given family out of a DNS response message.
 *
 * Only the answer section is looked at, and only its records of the wanted type (A for IPv4,
 * AAAA for IPv6) whose data has the size of an address are kept, in the order they appear.
 *
 * Throws if the message isn't a well-formed response.
 */
export declare function parseDnsMessageAnswer(message: Uint8Array, family: 4 | 6): string[];
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
export declare function resolveDnsOverHttps(hostname: string, family: 4 | 6 | undefined, signal: AbortSignal, fetchImpl?: typeof fetch, staggerMs?: number): Promise<string>;
