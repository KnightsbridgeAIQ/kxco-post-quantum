/// <reference types="node" />

export interface SlhDsaKeypair {
  /** 48-byte public key */
  publicKey: Buffer
  /** 96-byte secret key */
  secretKey: Buffer
}

/**
 * Generate an SLH-DSA-SHA2-192s (NIST FIPS 205) keypair deterministically
 * from a master + domain-separation info string.
 *
 * Same inputs always produce the same keypair — no state, no DB row.
 * Security Category 3, matching ML-DSA-65.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): SlhDsaKeypair

/** Maximum context length in bytes (FIPS 205, matching FIPS 204). */
export const MAX_CONTEXT_BYTES: 255

export interface SignatureOptions {
  /**
   * Optional context string, at most 255 bytes. Strings are encoded as UTF-8.
   * A signature made under a context does not verify without it. An empty
   * context is identical to omitting it.
   */
  context?: Buffer | Uint8Array | string
}

/**
 * Sign a message under an SLH-DSA-SHA2-192s secret key. Returns the signature
 * as a hex string (16224 bytes = 32448 hex characters).
 *
 * @throws {TypeError}  if `opts` is not an options object, or `context` is
 *                      neither a string nor a Uint8Array
 * @throws {RangeError} if `context` exceeds 255 bytes
 */
export function sign(
  secretKey: Buffer | Uint8Array,
  message:   Buffer | Uint8Array | string,
  opts?:     SignatureOptions,
): string

/**
 * Verify an SLH-DSA-SHA2-192s signature against a public key + message.
 *
 * The signature is the hex string `sign` returns, or the raw 16224 signature
 * bytes as a `Uint8Array` or `Buffer`.
 *
 * Returns `false` on any cryptographic failure (invalid hex, wrong length,
 * mismatch, a missing/incorrect context, or a value that is neither a string
 * nor a `Uint8Array`). Throws only on caller misuse of `opts`.
 *
 * @throws {TypeError}  if `opts` is not an options object, or `context` is
 *                      neither a string nor a Uint8Array
 * @throws {RangeError} if `context` exceeds 255 bytes
 */
export function verify(
  publicKey: Buffer | Uint8Array,
  message:   Buffer | Uint8Array | string,
  signature: string | Uint8Array,
  opts?:     SignatureOptions,
): boolean

/**
 * Raw `@noble/post-quantum` SLH-DSA-SHA2-192s primitive, re-exported for
 * callers who want the lower-level API. The wrapper functions above are
 * recommended for production use.
 */
export const slh_dsa_sha2_192s: typeof import('@noble/post-quantum/slh-dsa.js').slh_dsa_sha2_192s
