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

/**
 * Sign a message under an SLH-DSA-SHA2-192s secret key. Returns the signature
 * as a hex string (16224 bytes = 32448 hex characters).
 */
export function sign(
  secretKey: Buffer | Uint8Array,
  message:   Buffer | string,
): string

/**
 * Verify a hex-encoded SLH-DSA-SHA2-192s signature against a public key +
 * message. Returns `false` on any error (invalid hex, wrong length, mismatch).
 */
export function verify(
  publicKey: Buffer | Uint8Array,
  message:   Buffer | string,
  sigHex:    string,
): boolean

/**
 * Raw `@noble/post-quantum` SLH-DSA-SHA2-192s primitive, re-exported for
 * callers who want the lower-level API. The wrapper functions above are
 * recommended for production use.
 */
export const slh_dsa_sha2_192s: typeof import('@noble/post-quantum/slh-dsa.js').slh_dsa_sha2_192s
