// Public-key fingerprints (kid = "key identifier").
//
// Receivers pin a 16-hex fingerprint of the platform's public key, then
// compare against an X-KXCO-PQ-Kid header on every webhook. Fast rejection of
// stale or unknown keys without re-fetching the full 1952-byte public key on
// every request.
//
// Isomorphic: uses @noble/hashes/sha256 — runs identically in Node and
// browsers.

import { sha256 } from '@noble/hashes/sha2.js'

function hexToBytes(hex) {
  if (hex.length % 2) throw new Error('odd hex length')
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}

function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}

/**
 * Compute a stable 16-hex-character fingerprint of a public key.
 *
 * @param {Buffer|Uint8Array|string} publicKey — raw bytes or hex string
 * @returns {string} 16 hex chars (8 bytes of SHA-256)
 */
export function fingerprint(publicKey) {
  const bytes = typeof publicKey === 'string'
    ? hexToBytes(publicKey)
    : (publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey))
  return bytesToHex(sha256(bytes)).slice(0, 16)
}

/**
 * Constant-time comparison of two kid strings.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function kidEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
