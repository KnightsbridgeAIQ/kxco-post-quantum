/// <reference types="node" />

export interface MlDsaKeypair {
  /** 1952-byte public key */
  publicKey: Buffer
  /** 4032-byte secret key */
  secretKey: Buffer
}

/**
 * Generate an ML-DSA-65 (NIST FIPS 204) keypair deterministically
 * from a master + domain-separation info string.
 *
 * Same inputs always produce the same keypair — no state, no DB row.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): MlDsaKeypair

/**
 * Sign a message under an ML-DSA-65 secret key. Returns the signature
 * as a hex string (3309 bytes = 6618 hex characters).
 */
export function sign(
  secretKey: Buffer | Uint8Array,
  message:   Buffer | string,
): string

/**
 * Verify a hex-encoded ML-DSA-65 signature against a public key + message.
 * Returns `false` on any error (invalid hex, wrong length, mismatch).
 */
export function verify(
  publicKey: Buffer | Uint8Array,
  message:   Buffer | string,
  sigHex:    string,
): boolean

/**
 * Raw `@noble/post-quantum` ML-DSA-65 primitive, re-exported for callers
 * who want the lower-level API. The wrapper functions above are
 * recommended for production use.
 */
export const ml_dsa65: typeof import('@noble/post-quantum/ml-dsa.js').ml_dsa65
