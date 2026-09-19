// The same ACVP contract as responders.mjs, answered by OpenSSL instead of
// @noble/post-quantum.
//
// WHY THIS EXISTS. The package prefers the OpenSSL backend wherever the runtime
// provides it, and on any supported deployment that is what executes. Every
// graded case we hold, certificate A11025 included, was produced by the
// JavaScript backend, because responders.mjs binds to @noble directly. So the
// evidence and the deployment do not meet. This file is the attempt to make
// them meet.
//
// It does not fully succeed, and the shape of the failure is the useful part.
//
// WHAT OPENSSL CANNOT BE ASKED THROUGH NODE. ACVP does not only want an answer,
// it wants a REPRODUCIBLE answer: a keygen driven from NIST's seed, a signature
// using NIST's per-signature randomness. OpenSSL 3.5 takes those controls at
// its C API. Node's binding does not pass them on. Read out of Node's own
// source, crypto.sign looks for exactly one algorithm-specific option on the
// key object, which is context, and there is no deterministic, no rnd, no mu.
// Node also ignores unknown options in silence, so a harness that passed them
// would look like it worked and would be graded wrong.
//
// Rather than guess where that bites, every group this cannot express throws
// with the reason. selftest.mjs already reports a refusal by group, parameter
// set and message, so running this against NIST's published vectors prints the
// exact boundary instead of an opinion about it.
//
//   node conformance/acvts/selftest.mjs --native
//
// Nothing here is used at runtime by the package. It is conformance tooling.

import crypto from 'node:crypto'

// Parameter sets this OpenSSL build exposes. Anything absent has no native path
// at all and falls back to JavaScript in normal use, so it cannot be answered
// here even in principle.
const NODE_ALG = {
  'ML-KEM-512': 'ml-kem-512',
  'ML-KEM-768': 'ml-kem-768',
  'ML-KEM-1024': 'ml-kem-1024',
  'ML-DSA-44': 'ml-dsa-44',
  'ML-DSA-65': 'ml-dsa-65',
  'ML-DSA-87': 'ml-dsa-87',
  'SLH-DSA-SHA2-128f': 'slh-dsa-sha2-128f',
  'SLH-DSA-SHA2-192s': 'slh-dsa-sha2-192s',
  'SLH-DSA-SHAKE-256f': 'slh-dsa-shake-256f',
}

const hex = (u8) => Buffer.from(u8).toString('hex').toUpperCase()
const bytes = (h) => Buffer.from(h ?? '', 'hex')

const derLen = (n) =>
  n < 0x80 ? Buffer.from([n])
  : n < 0x100 ? Buffer.from([0x81, n])
  : Buffer.from([0x82, n >> 8, n & 0xff])
const der = (tag, payload) => Buffer.concat([Buffer.from([tag]), derLen(payload.length), payload])

// Read the AlgorithmIdentifier off a key OpenSSL generates itself, so a build
// that spells an OID differently cannot produce a subtly wrong encoding here.
const algidCache = new Map()
function algid(nodeName) {
  if (!algidCache.has(nodeName)) {
    const { privateKey } = crypto.generateKeyPairSync(nodeName)
    const p = privateKey.export({ format: 'der', type: 'pkcs8' })
    const headerLength = p[1] & 0x80 ? 2 + (p[1] & 0x7f) : 2
    const start = headerLength + 3 // skip the version INTEGER
    algidCache.set(nodeName, p.subarray(start, start + 2 + p[start + 1]))
  }
  return algidCache.get(nodeName)
}

const pkcs8 = (nodeName, inner) =>
  der(0x30, Buffer.concat([Buffer.from('020100', 'hex'), algid(nodeName), der(0x04, inner)]))

// The private key ASN.1 is a CHOICE. [0] IMPLICIT is the seed; a bare OCTET
// STRING is the expanded key. Both were verified against @noble before use:
// a key imported from a seed produces @noble's public key byte for byte, and a
// decapsulation under an imported expanded key produces @noble's shared secret.
const fromExpanded = (nodeName, sk) =>
  crypto.createPrivateKey({ key: pkcs8(nodeName, der(0x04, sk)), format: 'der', type: 'pkcs8' })

function publicKey(nodeName, raw) {
  const bits = der(0x03, Buffer.concat([Buffer.from([0x00]), raw]))
  return crypto.createPublicKey({
    key: der(0x30, Buffer.concat([algid(nodeName), bits])),
    format: 'der',
    type: 'spki',
  })
}

function refuse(g, why) {
  throw new Error(`tgId ${g.tgId} ${g.parameterSet ?? ''}: ${why}`.replace(/\s+/g, ' ').trim())
}

function nodeAlg(g) {
  const n = NODE_ALG[g.parameterSet]
  if (!n) refuse(g, `${g.parameterSet} has no native path in this OpenSSL build`)
  return n
}

// Shared gate for the two signature families. A group that needs a control Node
// does not pass through is refused here rather than answered wrongly.
function signatureGate(g) {
  if (g.signatureInterface === 'internal') {
    refuse(g, 'the internal interface is not reachable through node:crypto')
  }
  if (g.externalMu === true) {
    refuse(g, 'externalMu is not reachable: crypto.sign reads no mu option and ignores it in silence')
  }
  if (g.preHash === 'preHash') {
    refuse(g, 'pre-hash is refused by the provider: every digest returns invalid digest')
  }
}

function sigVer(prompt) {
  return prompt.testGroups.map((g) => {
    const alg = nodeAlg(g)
    signatureGate(g)
    return {
      tgId: g.tgId,
      tests: g.tests.map((t) => {
        // A negative vector can be malformed enough to throw. A throw and a
        // false return are the same verdict: the signature was rejected.
        let testPassed
        try {
          const key = publicKey(alg, bytes(t.pk))
          const opts = t.context !== undefined ? { key, context: bytes(t.context) } : key
          testPassed = crypto.verify(null, bytes(t.message), opts, bytes(t.signature)) === true
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
      nodeAlg(g)
      // ek is reproducible from the seed and matches @noble. dk is not: OpenSSL
      // stores and exports the 64-byte d || z seed, and there is no way to ask
      // it for the expanded decapsulation key that ACVP wants in the response.
      refuse(g, 'dk is not obtainable: OpenSSL exports the 64-byte seed, not the expanded decapsulation key')
    }),

  'ML-KEM/encapDecap': (prompt) =>
    prompt.testGroups.map((g) => {
      const alg = nodeAlg(g)
      if (g.function === 'encapsulation') {
        refuse(g, 'encapsulation needs the m from NIST as its randomness, and crypto.encapsulate takes no such option')
      }
      return {
        tgId: g.tgId,
        tests: g.tests.map((t) => {
          if (g.function === 'decapsulation') {
            return { tcId: t.tcId, k: hex(crypto.decapsulate(fromExpanded(alg, bytes(t.dk)), bytes(t.c))) }
          }
          if (g.function === 'encapsulationKeyCheck' || g.function === 'decapsulationKeyCheck') {
            let testPassed = true
            try {
              if (g.function === 'encapsulationKeyCheck') crypto.encapsulate(publicKey(alg, bytes(t.ek)))
              else fromExpanded(alg, bytes(t.dk))
            } catch {
              testPassed = false
            }
            return { tcId: t.tcId, testPassed }
          }
          return refuse(g, `unknown function ${g.function}`)
        }),
      }
    }),

  'ML-DSA/keyGen': (prompt) =>
    prompt.testGroups.map((g) => {
      nodeAlg(g)
      // Same shape as ML-KEM: pk is reproducible from the seed and matches
      // @noble byte for byte, sk is not obtainable in the expanded form.
      refuse(g, 'sk is not obtainable: OpenSSL exports the 32-byte seed, not the expanded signing key')
    }),

  'ML-DSA/sigGen': (prompt) =>
    prompt.testGroups.map((g) => {
      nodeAlg(g)
      refuse(g, 'signing randomness is not controllable: crypto.sign reads no deterministic and no rnd option')
    }),

  'ML-DSA/sigVer': (prompt) => sigVer(prompt),

  'SLH-DSA/keyGen': (prompt) =>
    prompt.testGroups.map((g) => {
      nodeAlg(g)
      refuse(g, 'keyGen from SK.seed, SK.prf and PK.seed is not reachable: OpenSSL imports a complete key only')
    }),

  'SLH-DSA/sigGen': (prompt) =>
    prompt.testGroups.map((g) => {
      nodeAlg(g)
      refuse(g, 'signing randomness is not controllable: crypto.sign reads no additionalRandomness option')
    }),

  'SLH-DSA/sigVer': (prompt) => sigVer(prompt),
}

export function respond(prompt) {
  const key = `${prompt.algorithm}/${prompt.mode}`
  const responder = RESPONDERS[key]
  if (!responder) throw new Error(`no native responder for ${key}`)
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
