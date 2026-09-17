// Turn an ACVP prompt from the live NIST server into an ACVP response.
//
// The computation is deliberately identical to conformance/run-acvp.mjs. That
// runner compares against NIST's published expected results; this one produces
// the answers the live server has not shown us. Keeping the two in step is the
// point: if they ever disagree, one of them is wrong and it matters which.
//
// A group the backend cannot express is NOT quietly dropped. It throws, because
// an unanswered test case in a live session is a failed validation, and a
// registration that claims a capability we cannot meet is the bug to fix.

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import * as slh from '@noble/post-quantum/slh-dsa.js'
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js'
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128_32, shake256_64 } from '@noble/hashes/sha3.js'

const KEM = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
}

const DSA = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
}

const SLH = {
  'SLH-DSA-SHA2-128s': slh.slh_dsa_sha2_128s,
  'SLH-DSA-SHA2-128f': slh.slh_dsa_sha2_128f,
  'SLH-DSA-SHA2-192s': slh.slh_dsa_sha2_192s,
  'SLH-DSA-SHA2-192f': slh.slh_dsa_sha2_192f,
  'SLH-DSA-SHA2-256s': slh.slh_dsa_sha2_256s,
  'SLH-DSA-SHA2-256f': slh.slh_dsa_sha2_256f,
  'SLH-DSA-SHAKE-128s': slh.slh_dsa_shake_128s,
  'SLH-DSA-SHAKE-128f': slh.slh_dsa_shake_128f,
  'SLH-DSA-SHAKE-192s': slh.slh_dsa_shake_192s,
  'SLH-DSA-SHAKE-192f': slh.slh_dsa_shake_192f,
  'SLH-DSA-SHAKE-256s': slh.slh_dsa_shake_256s,
  'SLH-DSA-SHAKE-256f': slh.slh_dsa_shake_256f,
}

const HASHES = {
  'SHA2-224': sha224,
  'SHA2-256': sha256,
  'SHA2-384': sha384,
  'SHA2-512': sha512,
  'SHA2-512/224': sha512_224,
  'SHA2-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  'SHAKE-128': shake128_32,
  'SHAKE-256': shake256_64,
}

const hex = (u8) => Buffer.from(u8).toString('hex').toUpperCase()
const bytes = (h) => Uint8Array.from(Buffer.from(h ?? '', 'hex'))

function backend(table, g) {
  const alg = table[g.parameterSet]
  if (!alg) throw new Error(`tgId ${g.tgId}: no backend for ${g.parameterSet}`)
  return alg
}

// Resolve the signing surface for one group. Mirrors signerFor() in run-acvp.mjs.
function signerFor(alg, g, t) {
  if (g.signatureInterface === 'internal') {
    if (!alg.internal) throw new Error(`tgId ${g.tgId}: backend exposes no internal interface`)
    return { signer: alg.internal, extraOpts: { externalMu: g.externalMu === true } }
  }
  if (g.preHash === 'preHash') {
    const hashName = g.hashAlg ?? t.hashAlg
    const hash = HASHES[hashName]
    if (!hash) throw new Error(`tgId ${g.tgId}: unsupported pre-hash ${hashName}`)
    return { signer: alg.prehash(hash), extraOpts: {} }
  }
  return { signer: alg, extraOpts: {} }
}

function sigGen(prompt, table, rndField) {
  return prompt.testGroups.map((g) => {
    const alg = backend(table, g)
    return {
      tgId: g.tgId,
      tests: g.tests.map((t) => {
        const { signer, extraOpts } = signerFor(alg, g, t)
        const opts = { ...extraOpts }
        if (g.signatureInterface !== 'internal' && t.context !== undefined) {
          opts.context = bytes(t.context)
        }
        // Deterministic groups fix the per-signature randomness to zero;
        // randomized groups supply it so the output is reproducible.
        opts.extraEntropy = g.deterministic === false ? bytes(t[rndField]) : false
        const msg = g.externalMu === true ? bytes(t.mu) : bytes(t.message)
        return { tcId: t.tcId, signature: hex(signer.sign(msg, bytes(t.sk), opts)) }
      }),
    }
  })
}

function sigVer(prompt, table) {
  return prompt.testGroups.map((g) => {
    const alg = backend(table, g)
    return {
      tgId: g.tgId,
      tests: g.tests.map((t) => {
        const { signer, extraOpts } = signerFor(alg, g, t)
        const opts = { ...extraOpts }
        if (g.signatureInterface !== 'internal' && t.context !== undefined) {
          opts.context = bytes(t.context)
        }
        const msg = g.externalMu === true ? bytes(t.mu) : bytes(t.message)
        // A negative vector can be malformed enough to throw. A throw and a
        // false return are the same verdict: the signature was rejected.
        let testPassed
        try {
          testPassed = signer.verify(bytes(t.signature), msg, bytes(t.pk), opts) === true
        } catch {
          testPassed = false
        }
        return { tcId: t.tcId, testPassed }
      }),
    }
  })
}

const RESPONDERS = {
  'ML-KEM/keyGen': (prompt) =>
    prompt.testGroups.map((g) => {
      const alg = backend(KEM, g)
      return {
        tgId: g.tgId,
        tests: g.tests.map((t) => {
          // FIPS 203 7.1 ML-KEM.KeyGen takes (d, z); the backend seed is d || z.
          const k = alg.keygen(Uint8Array.from([...bytes(t.d), ...bytes(t.z)]))
          return { tcId: t.tcId, ek: hex(k.publicKey), dk: hex(k.secretKey) }
        }),
      }
    }),

  'ML-KEM/encapDecap': (prompt) =>
    prompt.testGroups.map((g) => {
      const alg = backend(KEM, g)
      return {
        tgId: g.tgId,
        tests: g.tests.map((t) => {
          if (g.function === 'encapsulation') {
            const r = alg.encapsulate(bytes(t.ek), bytes(t.m))
            return { tcId: t.tcId, c: hex(r.cipherText ?? r.ciphertext), k: hex(r.sharedSecret) }
          }
          if (g.function === 'decapsulation') {
            return { tcId: t.tcId, k: hex(alg.decapsulate(bytes(t.c), bytes(t.dk))) }
          }
          if (g.function === 'encapsulationKeyCheck' || g.function === 'decapsulationKeyCheck') {
            // 7.2 / 7.3 input checks: a malformed key must be rejected.
            let testPassed = true
            try {
              if (g.function === 'encapsulationKeyCheck') alg.encapsulate(bytes(t.ek))
              else alg.decapsulate(new Uint8Array(alg.lengths.cipherText), bytes(t.dk))
            } catch {
              testPassed = false
            }
            return { tcId: t.tcId, testPassed }
          }
          throw new Error(`tgId ${g.tgId}: unknown function ${g.function}`)
        }),
      }
    }),

  'ML-DSA/keyGen': (prompt) =>
    prompt.testGroups.map((g) => {
      const alg = backend(DSA, g)
      return {
        tgId: g.tgId,
        tests: g.tests.map((t) => {
          const k = alg.keygen(bytes(t.seed))
          return { tcId: t.tcId, pk: hex(k.publicKey), sk: hex(k.secretKey) }
        }),
      }
    }),

  'ML-DSA/sigGen': (prompt) => sigGen(prompt, DSA, 'rnd'),
  'ML-DSA/sigVer': (prompt) => sigVer(prompt, DSA),

  'SLH-DSA/keyGen': (prompt) =>
    prompt.testGroups.map((g) => {
      const alg = backend(SLH, g)
      return {
        tgId: g.tgId,
        tests: g.tests.map((t) => {
          // FIPS 205 key generation takes (SK.seed, SK.prf, PK.seed) in order.
          const seed = Uint8Array.from([...bytes(t.skSeed), ...bytes(t.skPrf), ...bytes(t.pkSeed)])
          const k = alg.keygen(seed)
          return { tcId: t.tcId, pk: hex(k.publicKey), sk: hex(k.secretKey) }
        }),
      }
    }),

  'SLH-DSA/sigGen': (prompt) => sigGen(prompt, SLH, 'additionalRandomness'),
  'SLH-DSA/sigVer': (prompt) => sigVer(prompt, SLH),
}

export function respond(prompt) {
  const key = `${prompt.algorithm}/${prompt.mode}`
  const responder = RESPONDERS[key]
  if (!responder) throw new Error(`no responder for ${key}`)
  return {
    vsId: prompt.vsId,
    algorithm: prompt.algorithm,
    mode: prompt.mode,
    revision: prompt.revision,
    isSample: prompt.isSample === true,
    testGroups: responder(prompt),
  }
}

export const SUPPORTED = Object.keys(RESPONDERS)
