/**
 * Decodes a multibase-encoded string.
 *
 * Throws an exception if the encoding isn't base64 or one of its variants.
 */
export declare function multibaseBase64Decode(input: string): Uint8Array;
/**
 * Decodes a base64-encoded string into bytes using the original alphabet from RFC4648.
 *
 * See <https://datatracker.ietf.org/doc/html/rfc4648#section-4>.
 */
export declare function classicDecode(input: string): Uint8Array;
/**
 * Decodes a base64-encoded string into bytes using the URL-safe alphabet.
 *
 * See <https://datatracker.ietf.org/doc/html/rfc4648#section-5>.
 */
export declare function urlSafeDecode(input: string): Uint8Array;
/**
 * Decodes a base64-encoded string into bytes using the given alphabet.
 */
export declare function base64Decode(input: string, alphabet: Map<string, number>): Uint8Array;
