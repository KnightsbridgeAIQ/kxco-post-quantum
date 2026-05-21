/// <reference types="node" />

/**
 * Compute a 16-hex-character fingerprint of a public key:
 * the first 8 bytes of `SHA-256(public_key)`, hex-encoded.
 *
 * Stable for the lifetime of the keypair. Used to identify which
 * platform key signed an outbound delivery without including the
 * full 1952-byte public key in every request.
 *
 * @param publicKey — raw bytes or hex string
 */
export function fingerprint(publicKey: Buffer | Uint8Array | string): string

/**
 * Constant-time comparison of two kid strings.
 *
 * Use this instead of `===` when comparing kids that may be
 * influenced by untrusted input — eg. an `X-KXCO-PQ-Kid` header.
 */
export function kidEquals(a: string, b: string): boolean
