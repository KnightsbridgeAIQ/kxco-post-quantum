// ML-DSA-65 helpers (NIST FIPS 204, Dilithium3).
//
// Module-lattice signatures. Security Category 3 (≈ AES-192). Public key 1952
// bytes, signature 3309 bytes. Resistant to attacks by quantum computers.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (backwards compatible), Uint8Array in browsers.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa'
import { deriveSeed } from './derive.js'

const HAS_BUFFER = typeof Buffer !== 'undefined'
const enc = new TextEncoder()

function toBytes(input) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') return enc.encode(input)
  throw new Error('expected Uint8Array or string')
}
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('invalid hex')
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}
function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}
function wrap(bytes) {
  return HAS_BUFFER ? Buffer.from(bytes) : bytes
}

/**
 * Generate an ML-DSA-65 keypair from a master + domain-separation info.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'ml-dsa-65-v1') {
  const seed = deriveSeed(master, info, 32)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = ml_dsa65.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
  }
}

/**
 * Sign a message. Returns the signature as a hex string.
 *
 * @param {Buffer|Uint8Array} secretKey
 * @param {Buffer|Uint8Array|string} message
 * @returns {string} hex-encoded signature (6618 chars)
 */
export function sign(secretKey, message) {
  const sig = ml_dsa65.sign(secretKey, toBytes(message))
  return bytesToHex(sig)
}

/**
 * Verify a hex-encoded signature.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @param {Buffer|Uint8Array|string} message
 * @param {string} sigHex
 * @returns {boolean}
 */
export function verify(publicKey, message, sigHex) {
  try {
    return ml_dsa65.verify(publicKey, toBytes(message), hexToBytes(sigHex))
  } catch {
    return false
  }
}

export { ml_dsa65 }
