// ACVP responder for the supporting algorithms inside kxco-post-quantum/fips:
// SHA-2, SHA-3, SHAKE, HMAC and HMAC_DRBG. It computes with the module's own
// code (src/fips/vendor and src/fips/drbg.js), not the npm packages, because the
// module's bytes are what a validation would cover.
//
// `registered(group, test)` says whether NIST's server could send a test case
// under the registrations in registrations.mjs: whole-byte message and output
// lengths, no large-data tests, and HMAC_DRBG with SHA-512 and no prediction
// resistance. selftest.mjs uses it to filter NIST's sample files, which carry
// cases outside any one registration. A case the registration excludes and the
// server sends anyway throws, as in responders.mjs.

import { sha256, sha512 } from '../../src/fips/vendor/hashes/sha2.js'
import { sha3_256, sha3_512, shake128, shake256 } from '../../src/fips/vendor/hashes/sha3.js'
import { hmac } from '../../src/fips/vendor/hashes/hmac.js'
import { HmacDrbg } from '../../src/fips/drbg.js'

const HASH = { 'SHA2-256': sha256, 'SHA2-512': sha512, 'SHA3-256': sha3_256, 'SHA3-512': sha3_512 }
const XOF = { 'SHAKE-128': shake128, 'SHAKE-256': shake256 }

const bytes = (h) => Uint8Array.from(Buffer.from(h ?? '', 'hex'))
const hex = (u8) => Buffer.from(u8).toString('hex').toUpperCase()
const concat = (...a) => Uint8Array.from(Buffer.concat(a.map((x) => Buffer.from(x))))

export function registered(prompt, g, t) {
  if (g.testType === 'LDT') return false
  if (t?.len !== undefined && t.len % 8 !== 0) return false
  if (t?.outLen !== undefined && t.outLen % 8 !== 0) return false
  if (prompt.algorithm === 'hmacDRBG') return g.mode === 'SHA2-512' && !g.predResistance && !g.derFunc
  return true
}

// SHA-1/SHA-2 Monte Carlo test. The alternate version keeps every message at
// the seed's length, truncating or zero-padding A || B || C.
function mctSha2(fn, seed, alternate) {
  const out = []
  const len = seed.length
  for (let j = 0; j < 100; j++) {
    let a = seed, b = seed, c = seed
    for (let i = 0; i < 1000; i++) {
      let msg = concat(a, b, c)
      if (alternate) msg = msg.length >= len ? msg.subarray(0, len) : concat(msg, new Uint8Array(len - msg.length))
      const md = fn(msg)
      a = b; b = c; c = md
    }
    seed = c
    out.push({ md: hex(c) })
  }
  return out
}

// SHA-3 Monte Carlo test: each digest is the next message.
function mctSha3(fn, seed, alternate) {
  const out = []
  const len = seed.length
  let md = seed
  for (let j = 0; j < 100; j++) {
    for (let i = 0; i < 1000; i++) {
      let msg = md
      if (alternate) msg = msg.length >= len ? msg.subarray(0, len) : concat(msg, new Uint8Array(len - msg.length))
      md = fn(msg)
    }
    out.push({ md: hex(md) })
  }
  return out
}

function hashGroup(prompt, g) {
  const fn = HASH[prompt.algorithm]
  const isSha3 = prompt.algorithm.startsWith('SHA3')
  return g.tests.map((t) => {
    if (!registered(prompt, g, t)) throw new Error(`tgId ${g.tgId} tcId ${t.tcId}: outside the registration`)
    const msg = bytes(t.msg).subarray(0, t.len / 8)
    if (g.testType === 'AFT') return { tcId: t.tcId, md: hex(fn(msg)) }
    if (g.testType === 'MCT') {
      const alternate = g.mctVersion === 'alternate'
      return { tcId: t.tcId, resultsArray: isSha3 ? mctSha3(fn, msg, alternate) : mctSha2(fn, msg, alternate) }
    }
    throw new Error(`tgId ${g.tgId}: test type ${g.testType} not supported`)
  })
}

function xofGroup(prompt, g) {
  const fn = XOF[prompt.algorithm]
  return g.tests.map((t) => {
    if (!registered(prompt, g, t) || g.testType !== 'AFT') throw new Error(`tgId ${g.tgId} tcId ${t.tcId}: outside the registration`)
    return { tcId: t.tcId, md: hex(fn(bytes(t.msg).subarray(0, t.len / 8), { dkLen: t.outLen / 8 })) }
  })
}

function hmacGroup(prompt, g) {
  return g.tests.map((t) => {
    if (!registered(prompt, g, t)) throw new Error(`tgId ${g.tgId} tcId ${t.tcId}: outside the registration`)
    const mac = hmac(sha512, bytes(t.key), bytes(t.msg))
    return { tcId: t.tcId, mac: hex(mac.subarray(0, t.macLen / 8)) }
  })
}

function drbgGroup(prompt, g) {
  if (!registered(prompt, g)) throw new Error(`tgId ${g.tgId}: ${g.mode} predResistance=${g.predResistance} is outside the registration`)
  return g.tests.map((t) => {
    const d = new HmacDrbg()
    d.instantiate(bytes(t.entropyInput), bytes(t.nonce), bytes(t.persoString))
    let out
    for (const o of t.otherInput) {
      if (o.intendedUse === 'reSeed') d.reseed(bytes(o.entropyInput), bytes(o.additionalInput))
      else out = d.generate(g.returnedBitsLen / 8, bytes(o.additionalInput))
    }
    d.uninstantiate()
    return { tcId: t.tcId, returnedBits: hex(out) }
  })
}

export function respond(prompt) {
  const a = prompt.algorithm
  const group = HASH[a] ? hashGroup : XOF[a] ? xofGroup : a === 'HMAC-SHA2-512' ? hmacGroup : a === 'hmacDRBG' ? drbgGroup : null
  if (!group) throw new Error(`no FIPS-module responder for ${a}`)
  return {
    vsId: prompt.vsId,
    algorithm: a,
    revision: prompt.revision,
    testGroups: prompt.testGroups.map((g) => ({ tgId: g.tgId, tests: group(prompt, g) })),
  }
}

export const SUPPORTED = [...Object.keys(HASH), ...Object.keys(XOF), 'HMAC-SHA2-512', 'hmacDRBG']
