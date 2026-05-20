// ML-KEM-768 helpers (NIST FIPS 203, Kyber768).
//
// Module-lattice key encapsulation. Security Category 3 (≈ AES-192). Public
// key 1184 bytes, ciphertext 1088 bytes, shared secret 32 bytes. Resistant
// to attacks by quantum computers.
//
// Encapsulate to a recipient's public key: returns a ciphertext to transmit
// and a shared secret to use as a symmetric key. Decapsulate with the secret
// key to recover the same shared secret.

import { ml_kem768 } from '@noble/post-quantum/ml-kem'
import { deriveSeed } from './derive.js'

/**
 * Generate an ML-KEM-768 keypair from a master + domain-separation info.
 * Deterministic — same inputs always produce the same keypair.
 *
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
export function keypairFromMaster(master, info = 'ml-kem-768-v1') {
  const seed = deriveSeed(master, info, 64)
  const k = ml_kem768.keygen(seed)
  return {
    publicKey: Buffer.from(k.publicKey),
    secretKey: Buffer.from(k.secretKey),
  }
}

/**
 * Encapsulate a shared secret to the recipient's public key.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
 *   — transmit ciphertext to the recipient; use sharedSecret as a symmetric key
 */
export function encapsulate(publicKey) {
  const r = ml_kem768.encapsulate(publicKey)
  // @noble/post-quantum exposes `cipherText` (camelCase). Normalise to the
  // more standard `ciphertext` for callers; both fields are returned.
  const ct = Buffer.from(r.cipherText ?? r.ciphertext)
  return {
    ciphertext:   ct,
    cipherText:   ct,
    sharedSecret: Buffer.from(r.sharedSecret),
  }
}

/**
 * Decapsulate: recover the shared secret from a ciphertext using the secret key.
 *
 * @param {Buffer|Uint8Array} ciphertext
 * @param {Buffer|Uint8Array} secretKey
 * @returns {Buffer} shared secret (32 bytes)
 */
export function decapsulate(ciphertext, secretKey) {
  return Buffer.from(ml_kem768.decapsulate(ciphertext, secretKey))
}

export { ml_kem768 }
