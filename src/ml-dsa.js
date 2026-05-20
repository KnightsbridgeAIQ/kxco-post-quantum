// ML-DSA-65 helpers (NIST FIPS 204, Dilithium3).
//
// Module-lattice signatures. Security Category 3 (≈ AES-192). Public key 1952
// bytes, signature 3309 bytes. Resistant to attacks by quantum computers.
//
// This module wraps @noble/post-quantum with deterministic keygen-from-seed
// and ergonomic buffer-in/hex-out helpers used throughout KXCO production.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa'
import { deriveSeed } from './derive.js'

/**
 * Generate an ML-DSA-65 keypair from a master + domain-separation info.
 * Same inputs always produce the same keypair — no state, no DB row.
 *
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
export function keypairFromMaster(master, info = 'ml-dsa-65-v1') {
  const seed = deriveSeed(master, info, 32)
  const k = ml_dsa65.keygen(seed)
  return {
    publicKey: Buffer.from(k.publicKey),
    secretKey: Buffer.from(k.secretKey),
  }
}

/**
 * Sign a message. Returns the signature as a hex string.
 *
 * @param {Buffer|Uint8Array} secretKey
 * @param {Buffer|string}      message
 * @returns {string} hex-encoded signature (6618 chars)
 */
export function sign(secretKey, message) {
  const msg = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8')
  const sig = ml_dsa65.sign(secretKey, msg)
  return Buffer.from(sig).toString('hex')
}

/**
 * Verify a hex-encoded signature.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @param {Buffer|string}      message
 * @param {string}             sigHex
 * @returns {boolean}
 */
export function verify(publicKey, message, sigHex) {
  const msg = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8')
  try {
    return ml_dsa65.verify(publicKey, msg, Buffer.from(sigHex, 'hex'))
  } catch {
    return false
  }
}

// Re-export the raw noble primitive for callers who want the lower-level API.
export { ml_dsa65 }
