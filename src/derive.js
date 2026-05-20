// Deterministic key derivation via HKDF-SHA-512.
//
// Same seed + same info = same keypair, every time. This is how the KXCO
// platform reproduces its signing identity across replicas without storing
// the private key in a database: the master key is the env var, the rest is
// pure derivation.
//
// Domain separation through `info` is critical — using the same master key
// for different purposes (signing vs encryption) MUST use distinct info
// strings or you create a cross-protocol attack surface.

import { hkdfSync } from 'node:crypto'

/**
 * Derive a deterministic seed from a master secret + an info string.
 *
 * @param {Buffer|Uint8Array} master   — high-entropy input keying material
 * @param {string}             info    — domain separation tag (eg. 'kxco-platform-ml-dsa-65-v1')
 * @param {number}             length  — output seed length in bytes (32 for ML-DSA, 64 for ML-KEM)
 * @returns {Buffer}
 */
export function deriveSeed(master, info, length) {
  if (!master || master.length < 16) {
    throw new Error('deriveSeed: master keying material must be at least 16 bytes')
  }
  if (!info || typeof info !== 'string') {
    throw new Error('deriveSeed: info string is required for domain separation')
  }
  // Empty salt with HKDF-SHA-512 is fine when master has high entropy.
  return Buffer.from(
    hkdfSync('sha512', master, Buffer.alloc(32), Buffer.from(info, 'utf8'), length)
  )
}
