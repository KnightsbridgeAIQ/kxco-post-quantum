// HMAC_DRBG with SHA-512, as specified in NIST SP 800-90A Rev. 1 section 10.1.2.
//
// The approved random bit generator inside the FIPS module. Every random value
// the module's algorithms consume (key seeds, encapsulation randomness, hedged
// signing randomness) comes from an instance of this class, never from
// crypto.getRandomValues.
//
// This file is deterministic: it is given its entropy input and nonce, and has
// no source of its own. Where the entropy comes from is decided in module.js,
// which keeps the generator testable against NIST's vectors.
//
// Security strength 256 bits. Prediction resistance is not offered.

import { hmac } from './vendor/hashes/hmac.js'
import { sha512 } from './vendor/hashes/sha2.js'

const OUTLEN = 64 // SHA-512 output, bytes
export const SECURITY_STRENGTH = 256 // bits
// SP 800-90A Table 2 for HMAC_DRBG: at most 2^19 bits per request and 2^48
// requests between reseeds. The interval here is far tighter than the maximum,
// so a long-running process reseeds from the entropy source regularly.
export const MAX_BYTES_PER_REQUEST = 65536
export const RESEED_INTERVAL = 2 ** 20
// Entropy input must carry at least the security strength; the nonce at least
// half of it (SP 800-90A section 8.6.7).
export const MIN_ENTROPY_BYTES = SECURITY_STRENGTH / 8
export const MIN_NONCE_BYTES = SECURITY_STRENGTH / 16

function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

const EMPTY = new Uint8Array(0)

export class HmacDrbg {
  #K = null
  #V = null
  #counter = 0

  // SP 800-90A section 10.1.2.3.
  instantiate(entropyInput, nonce, personalization = EMPTY) {
    if (entropyInput.length < MIN_ENTROPY_BYTES) throw new Error('DRBG: entropy input below the security strength')
    if (nonce.length < MIN_NONCE_BYTES) throw new Error('DRBG: nonce below half the security strength')
    this.#K = new Uint8Array(OUTLEN)
    this.#V = new Uint8Array(OUTLEN).fill(0x01)
    this.#update(concat(entropyInput, nonce, personalization))
    this.#counter = 1
  }

  // SP 800-90A section 10.1.2.4.
  reseed(entropyInput, additionalInput = EMPTY) {
    this.#requireInstantiated()
    if (entropyInput.length < MIN_ENTROPY_BYTES) throw new Error('DRBG: entropy input below the security strength')
    this.#update(concat(entropyInput, additionalInput))
    this.#counter = 1
  }

  // Whether the next generate call must be preceded by a reseed.
  get reseedRequired() {
    return this.#counter > RESEED_INTERVAL
  }

  // SP 800-90A section 10.1.2.5. Returns a fresh Uint8Array of `bytes` bytes.
  generate(bytes, additionalInput = EMPTY) {
    this.#requireInstantiated()
    if (!Number.isInteger(bytes) || bytes < 1 || bytes > MAX_BYTES_PER_REQUEST) {
      throw new Error('DRBG: requested length out of range')
    }
    if (this.reseedRequired) throw new Error('DRBG: reseed required')
    if (additionalInput.length > 0) this.#update(additionalInput)
    const out = new Uint8Array(bytes)
    let filled = 0
    while (filled < bytes) {
      this.#V = hmac(sha512, this.#K, this.#V)
      const take = Math.min(OUTLEN, bytes - filled)
      out.set(this.#V.subarray(0, take), filled)
      filled += take
    }
    this.#update(additionalInput)
    this.#counter += 1
    return out
  }

  // SP 800-90A section 9.4: destroy the internal state.
  uninstantiate() {
    if (this.#K) this.#K.fill(0)
    if (this.#V) this.#V.fill(0)
    this.#K = null
    this.#V = null
    this.#counter = 0
  }

  get instantiated() {
    return this.#K !== null
  }

  // SP 800-90A section 10.1.2.2.
  #update(provided) {
    const oldK = this.#K
    this.#K = hmac(sha512, this.#K, concat(this.#V, [0x00], provided))
    oldK.fill(0)
    this.#V = hmac(sha512, this.#K, this.#V)
    if (provided.length === 0) return
    const k1 = this.#K
    this.#K = hmac(sha512, this.#K, concat(this.#V, [0x01], provided))
    k1.fill(0)
    this.#V = hmac(sha512, this.#K, this.#V)
  }

  #requireInstantiated() {
    if (this.#K === null) throw new Error('DRBG: not instantiated')
  }
}
