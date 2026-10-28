// The FIPS module's services. Loaded by index.js only after the module's files
// have passed the integrity test.
//
// Every random value an algorithm consumes is drawn from the module's own
// HMAC_DRBG and passed to the algorithm explicitly. Nothing here, and nothing
// it calls, reaches crypto.getRandomValues.

import { HmacDrbg } from './drbg.js'
import { getEntropy } from './entropy.js'
import { ml_kem768, ml_kem1024 } from './vendor/post-quantum/ml-kem.js'
import { ml_dsa65, ml_dsa87 } from './vendor/post-quantum/ml-dsa.js'
import { runAlgorithmCasts, FipsFatalError } from './selftest.js'

const KEM = { 'ML-KEM-768': ml_kem768, 'ML-KEM-1024': ml_kem1024 }
const DSA = { 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }
export const ALGORITHMS = Object.freeze([...Object.keys(KEM), ...Object.keys(DSA)])

// Entropy requested from outside the boundary per call, fixed so the Security
// Policy can state it: 384 bits of entropy input against the DRBG's 256-bit
// security strength, and a 256-bit nonce at instantiation.
export const ENTROPY_BYTES = 48
export const NONCE_BYTES = 32
const enc = new TextEncoder()
const PERSONALIZATION = enc.encode('kxco-post-quantum/fips HMAC_DRBG v1')
const PCT_MESSAGE = enc.encode('kxco-post-quantum/fips pairwise consistency test')
const MAX_CONTEXT_BYTES = 255

function toBytes(input, what) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') return enc.encode(input)
  throw new TypeError(`${what} must be a Uint8Array or a string`)
}
function requireBytes(input, what) {
  if (!(input instanceof Uint8Array)) throw new TypeError(`${what} must be a Uint8Array`)
  return input
}
function contextOf(opts) {
  if (opts === undefined) return new Uint8Array(0)
  if (opts === null || typeof opts !== 'object') throw new TypeError('options must be an object such as { context }')
  if (opts.context === undefined) return new Uint8Array(0)
  const ctx = toBytes(opts.context, 'context')
  if (ctx.length > MAX_CONTEXT_BYTES) throw new RangeError(`context must be at most ${MAX_CONTEXT_BYTES} bytes`)
  return ctx
}
function kemOf(alg) {
  const k = typeof alg === 'string' && Object.hasOwn(KEM, alg) ? KEM[alg] : undefined
  if (!k) throw new RangeError(`'${alg}' is not an ML-KEM parameter set this module offers (${Object.keys(KEM).join(', ')})`)
  return k
}
function dsaOf(alg) {
  const d = typeof alg === 'string' && Object.hasOwn(DSA, alg) ? DSA[alg] : undefined
  if (!d) throw new RangeError(`'${alg}' is not an ML-DSA parameter set this module offers (${Object.keys(DSA).join(', ')})`)
  return d
}
function equal(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}
export function zeroize(...arrays) {
  for (const a of arrays) if (a instanceof Uint8Array) a.fill(0)
}

// Starts the module: the algorithm self-tests, then the DRBG. Returns the
// service table index.js calls, or throws FipsFatalError.
export function start() {
  runAlgorithmCasts(HmacDrbg)

  const drbg = new HmacDrbg()
  try {
    const entropy = getEntropy(ENTROPY_BYTES)
    const nonce = getEntropy(NONCE_BYTES)
    drbg.instantiate(entropy, nonce, PERSONALIZATION)
    zeroize(entropy, nonce)
  } catch (err) {
    throw new FipsFatalError(`DRBG instantiation failed: ${err.message}`)
  }

  function random(length) {
    try {
      if (drbg.reseedRequired) {
        const entropy = getEntropy(ENTROPY_BYTES)
        drbg.reseed(entropy)
        zeroize(entropy)
      }
      return drbg.generate(length)
    } catch (err) {
      throw new FipsFatalError(`DRBG failed: ${err.message}`)
    }
  }

  // Pairwise consistency tests (IG 10.3.A), run on every generated key pair.
  // Any exception inside one is a failure of the test, so it is fatal too.
  function pctKem(kem, publicKey, secretKey) {
    let ok = false
    try {
      const m = random(32)
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey, m)
      const recovered = kem.decapsulate(cipherText, secretKey)
      ok = equal(sharedSecret, recovered)
      zeroize(m, sharedSecret, recovered)
    } catch (err) {
      if (err instanceof FipsFatalError) throw err
    }
    if (!ok) throw new FipsFatalError('pairwise consistency test failed for a generated ML-KEM key pair')
  }
  function pctDsa(dsa, publicKey, secretKey) {
    let ok = false
    try {
      const rnd = random(32)
      const sig = dsa.sign(PCT_MESSAGE, secretKey, { extraEntropy: rnd })
      zeroize(rnd)
      ok = dsa.verify(sig, PCT_MESSAGE, publicKey) === true
    } catch (err) {
      if (err instanceof FipsFatalError) throw err
    }
    if (!ok) throw new FipsFatalError('pairwise consistency test failed for a generated ML-DSA key pair')
  }

  return {
    // A new key pair from a DRBG-drawn seed. The seed is returned because it is
    // the compact form of the key the operator stores; keypairFromSeed
    // re-expands it later (IG 10.3.A: reconstitution, no new test needed).
    generateKeypair(alg) {
      if (!ALGORITHMS.includes(alg)) throw new RangeError(`'${alg}' is not a parameter set this module offers (${ALGORITHMS.join(', ')})`)
      if (Object.hasOwn(KEM, alg)) {
        const kem = KEM[alg]
        const seed = random(64)
        const { publicKey, secretKey } = kem.keygen(seed)
        pctKem(kem, publicKey, secretKey)
        return { alg, publicKey, secretKey, seed }
      }
      const dsa = dsaOf(alg)
      const seed = random(32)
      const { publicKey, secretKey } = dsa.keygen(seed)
      pctDsa(dsa, publicKey, secretKey)
      return { alg, publicKey, secretKey, seed }
    },

    // Re-expand a stored seed, or take in a seed made elsewhere. The module does
    // not claim to have generated a seed it was given.
    keypairFromSeed(alg, seed) {
      if (!ALGORITHMS.includes(alg)) throw new RangeError(`'${alg}' is not a parameter set this module offers (${ALGORITHMS.join(', ')})`)
      requireBytes(seed, 'seed')
      if (Object.hasOwn(KEM, alg)) {
        if (seed.length !== 64) throw new RangeError(`${alg} seed must be 64 bytes, got ${seed.length}`)
        const { publicKey, secretKey } = KEM[alg].keygen(seed)
        return { alg, publicKey, secretKey }
      }
      const dsa = dsaOf(alg)
      if (seed.length !== 32) throw new RangeError(`${alg} seed must be 32 bytes, got ${seed.length}`)
      const { publicKey, secretKey } = dsa.keygen(seed)
      return { alg, publicKey, secretKey }
    },

    // FIPS 203 section 7.2 input checks run inside the algorithm: a malformed
    // encapsulation key throws rather than producing a ciphertext.
    encapsulate(alg, publicKey) {
      const kem = kemOf(alg)
      requireBytes(publicKey, 'publicKey')
      const m = random(32)
      try {
        const { cipherText, sharedSecret } = kem.encapsulate(publicKey, m)
        return { cipherText, sharedSecret }
      } finally {
        zeroize(m)
      }
    },

    // FIPS 203 section 7.3 input checks run inside the algorithm. A ciphertext
    // that does not decapsulate correctly yields the implicit-rejection secret,
    // as FIPS 203 requires, not an error.
    decapsulate(alg, cipherText, secretKey) {
      const kem = kemOf(alg)
      requireBytes(cipherText, 'cipherText')
      requireBytes(secretKey, 'secretKey')
      return kem.decapsulate(cipherText, secretKey)
    },

    // Hedged ML-DSA signing (FIPS 204 Algorithm 2), randomness from the DRBG.
    sign(alg, secretKey, message, opts) {
      const dsa = dsaOf(alg)
      requireBytes(secretKey, 'secretKey')
      const context = contextOf(opts)
      const msg = toBytes(message, 'message')
      const rnd = random(32)
      try {
        return dsa.sign(msg, secretKey, { context, extraEntropy: rnd })
      } finally {
        zeroize(rnd)
      }
    },

    // Returns false for any signature that does not verify. Throws only on
    // caller misuse (unknown parameter set, bad options).
    verify(alg, publicKey, message, signature, opts) {
      const dsa = dsaOf(alg)
      const context = contextOf(opts)
      const msg = toBytes(message, 'message')
      requireBytes(publicKey, 'publicKey')
      requireBytes(signature, 'signature')
      try {
        return dsa.verify(signature, msg, publicKey, { context }) === true
      } catch {
        return false
      }
    },

    runCasts() {
      runAlgorithmCasts(HmacDrbg)
    },

    // Zeroise the module's own secret state on entering the error state.
    destroy() {
      drbg.uninstantiate()
    },
  }
}
