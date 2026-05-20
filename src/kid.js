// Public-key fingerprints (kid = "key identifier").
//
// Receivers pin a 16-hex fingerprint of the platform's public key, then
// compare against an X-KXCO-PQ-Kid header on every webhook. Fast rejection of
// stale or unknown keys without re-fetching the full 1952-byte public key on
// every request.

import { createHash } from 'node:crypto'

/**
 * Compute a stable, 16-hex-character fingerprint of a public key.
 *
 * @param {Buffer|Uint8Array|string} publicKey  — raw bytes or hex string
 * @returns {string} 16 hex chars (8 bytes of SHA-256)
 */
export function fingerprint(publicKey) {
  const buf = typeof publicKey === 'string'
    ? Buffer.from(publicKey, 'hex')
    : Buffer.from(publicKey)
  return createHash('sha256').update(buf).digest('hex').slice(0, 16)
}

/**
 * Constant-time comparison of two kid strings. Use this instead of `===`
 * when comparing kids from user input.
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
