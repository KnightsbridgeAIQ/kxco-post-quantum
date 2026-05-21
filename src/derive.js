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
//
// Isomorphic: uses @noble/hashes/hkdf which runs identically in Node 18+ and
// modern browsers. Returns Buffer when running on Node (for backwards
// compatibility with existing callers), Uint8Array in browsers.

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha512 } from '@noble/hashes/sha2.js'

const HAS_BUFFER = typeof Buffer !== 'undefined'
const enc = new TextEncoder()

function toBytes(input) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') return enc.encode(input)
  throw new Error('expected Uint8Array or string')
}

/**
 * Derive a deterministic seed from a master secret + an info string.
 *
 * @param {Buffer|Uint8Array|string} master   — high-entropy keying material (>= 16 bytes)
 * @param {string}                    info    — domain separation tag
 * @param {number}                    length  — output seed length in bytes
 * @returns {Buffer|Uint8Array}
 */
export function deriveSeed(master, info, length) {
  const ikm = toBytes(master)
  if (!ikm || ikm.length < 16) {
    throw new Error('deriveSeed: master keying material must be at least 16 bytes')
  }
  if (!info || typeof info !== 'string') {
    throw new Error('deriveSeed: info string is required for domain separation')
  }
  const salt = new Uint8Array(32) // 32 zero bytes — fine with high-entropy IKM
  const out = hkdf(sha512, ikm, salt, enc.encode(info), length)
  return HAS_BUFFER ? Buffer.from(out) : out
}
