#!/usr/bin/env node
// Build src/fips/kat.js, the known answers the FIPS module's self-tests check.
//
// Every value is taken from NIST's own ACVP vector files, pinned by digest in
// conformance/acvp-lock.json, by a fixed selection rule written below, so anyone
// can regenerate the file and get the same bytes. Nothing in kat.js is computed
// by this package's own code.
//
//   node conformance/fetch-vectors.mjs     (once, to fetch and verify the vectors)
//   node scripts/build-fips-kat.mjs        write src/fips/kat.js
//   node scripts/build-fips-kat.mjs --check   exit 1 if src/fips/kat.js differs
//
// Outputs longer than 64 bytes are stored as their SHA-256 digest, and the
// self-test compares the digest of what it computed. Inputs are stored in full.

import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { vectorPath, acvpSource } from '../conformance/fetch-vectors.mjs'
import { shake256 } from '../src/fips/vendor/hashes/sha3.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(ROOT, 'src', 'fips', 'kat.js')

const load = (set, file) => {
  const j = JSON.parse(readFileSync(vectorPath(set, file), 'utf8'))
  return Array.isArray(j) ? j[1] : j
}
const expectedById = (set) => {
  const m = new Map()
  for (const g of load(set, 'expectedResults').testGroups) for (const t of g.tests) m.set(t.tcId, t)
  return m
}
const lower = (h) => h.toLowerCase()
const digest = (h) => createHash('sha256').update(Buffer.from(h, 'hex')).digest('hex')
const firstGroup = (set, pred) => {
  const g = load(set, 'prompt').testGroups.find(pred)
  if (!g) throw new Error(`no group in ${set} matches the selection rule`)
  return g
}

const kat = {}
const provenance = {}

// SHA-256 and SHA-512: the first non-empty message in the first AFT group.
for (const [name, set] of [['sha256', 'SHA2-256-1.0'], ['sha512', 'SHA2-512-1.0']]) {
  const g = firstGroup(set, (g) => g.testType === 'AFT')
  const t = g.tests.find((t) => t.len > 0)
  kat[name] = { msg: lower(t.msg), md: lower(expectedById(set).get(t.tcId).md) }
  provenance[name] = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// HMAC-SHA2-512: the first test. NIST's sample file carries only truncated tags,
// so the self-test compares the leftmost bytes of the full tag with `mac`.
{
  const set = 'HMAC-SHA2-512-2.0'
  const g = firstGroup(set, () => true)
  const t = g.tests[0]
  kat.hmacSha512 = { key: lower(t.key), msg: lower(t.msg), mac: lower(expectedById(set).get(t.tcId).mac) }
  provenance.hmacSha512 = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// HMAC_DRBG SHA-512, no prediction resistance, with reseed: the first test.
// It exercises instantiate, reseed and generate, the three functions SP 800-90A
// section 11.3 requires health tests for.
{
  const set = 'hmacDRBG-1.0'
  const g = firstGroup(set, (g) => g.mode === 'SHA2-512' && !g.predResistance && g.reSeed)
  const t = g.tests[0]
  kat.hmacDrbg = {
    entropyInput: lower(t.entropyInput),
    nonce: lower(t.nonce),
    personalization: lower(t.persoString),
    steps: t.otherInput.map((o) => ({ use: o.intendedUse, entropyInput: lower(o.entropyInput), additionalInput: lower(o.additionalInput) })),
    returnedBytes: g.returnedBitsLen / 8,
    returnedSha256: digest(expectedById(set).get(t.tcId).returnedBits),
  }
  provenance.hmacDrbg = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// ML-KEM-1024 key generation: the first test.
{
  const set = 'ML-KEM-keyGen-FIPS203'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-KEM-1024')
  const t = g.tests[0]
  const e = expectedById(set).get(t.tcId)
  kat.mlKemKeygen = { d: lower(t.d), z: lower(t.z), ekSha256: digest(e.ek), dkSha256: digest(e.dk) }
  provenance.mlKemKeygen = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// ML-KEM-1024 encapsulation: the first test.
{
  const set = 'ML-KEM-encapDecap-FIPS203'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-KEM-1024' && g.function === 'encapsulation')
  const t = g.tests[0]
  const e = expectedById(set).get(t.tcId)
  kat.mlKemEncaps = { ek: lower(t.ek), m: lower(t.m), cSha256: digest(e.c), k: lower(e.k) }
  provenance.mlKemEncaps = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// ML-KEM-1024 decapsulation: the first test that decapsulates normally and the
// first that exercises implicit rejection. NIST does not label which is which;
// a rejection case is one whose expected secret is J(z || c) = SHAKE256(z || c),
// with z the last 32 bytes of dk (FIPS 203 Algorithm 18).
{
  const set = 'ML-KEM-encapDecap-FIPS203'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-KEM-1024' && g.function === 'decapsulation')
  const exp = expectedById(set)
  const isRejection = (t) => {
    const dk = Buffer.from(t.dk, 'hex')
    const j = shake256(new Uint8Array(Buffer.concat([dk.subarray(dk.length - 32), Buffer.from(t.c, 'hex')])), { dkLen: 32 })
    return Buffer.from(j).toString('hex') === lower(exp.get(t.tcId).k)
  }
  const ok = g.tests.find((t) => !isRejection(t))
  const rej = g.tests.find((t) => isRejection(t))
  if (!ok || !rej) throw new Error('ML-KEM-1024 decapsulation group lacks a normal or an implicit-rejection case')
  kat.mlKemDecaps = { dk: lower(ok.dk), c: lower(ok.c), k: lower(exp.get(ok.tcId).k) }
  kat.mlKemReject = { dk: lower(rej.dk), c: lower(rej.c), k: lower(exp.get(rej.tcId).k) }
  provenance.mlKemDecaps = `${set} tgId ${g.tgId} tcId ${ok.tcId}`
  provenance.mlKemReject = `${set} tgId ${g.tgId} tcId ${rej.tcId} (implicit rejection)`
}

// ML-DSA-87 key generation: the first test.
{
  const set = 'ML-DSA-keyGen-FIPS204'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-DSA-87')
  const t = g.tests[0]
  const e = expectedById(set).get(t.tcId)
  kat.mlDsaKeygen = { seed: lower(t.seed), pkSha256: digest(e.pk), skSha256: digest(e.sk) }
  provenance.mlDsaKeygen = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// ML-DSA-87 signing: the first test of the external, pure, hedged group, which
// is the interface the module offers. The vector supplies the randomness.
{
  const set = 'ML-DSA-sigGen-FIPS204'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-DSA-87' && g.signatureInterface === 'external' &&
    g.preHash === 'pure' && g.deterministic === false)
  const t = g.tests[0]
  kat.mlDsaSign = {
    sk: lower(t.sk), message: lower(t.message), context: lower(t.context ?? ''), rnd: lower(t.rnd),
    signatureSha256: digest(expectedById(set).get(t.tcId).signature),
  }
  provenance.mlDsaSign = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

// ML-DSA-87 verification: the first passing test of the external, pure group.
{
  const set = 'ML-DSA-sigVer-FIPS204'
  const g = firstGroup(set, (g) => g.parameterSet === 'ML-DSA-87' && g.signatureInterface === 'external' && g.preHash === 'pure')
  const exp = expectedById(set)
  const t = g.tests.find((t) => exp.get(t.tcId).testPassed === true)
  kat.mlDsaVerify = { pk: lower(t.pk), message: lower(t.message), context: lower(t.context ?? ''), signature: lower(t.signature) }
  provenance.mlDsaVerify = `${set} tgId ${g.tgId} tcId ${t.tcId}`
}

const src = acvpSource()
const body =
`// Generated by scripts/build-fips-kat.mjs. Do not edit.
//
// Known answers for the FIPS module's self-tests, taken from NIST's ACVP vector
// files at ${src.repo}@${src.commit}
// (${src.path}), pinned by digest in conformance/acvp-lock.json.
// Hex throughout. Fields ending Sha256 hold the SHA-256 digest of an output
// longer than 64 bytes.
//
// Source of each entry:
${Object.entries(provenance).map(([k, v]) => `//   ${k}: ${v}`).join('\n')}

export const KAT = ${JSON.stringify(kat, null, 2)}
`

if (process.argv.includes('--check')) {
  let have = ''
  try { have = readFileSync(OUT, 'utf8') } catch {}
  if (have !== body) {
    console.error('src/fips/kat.js does not match the pinned NIST vectors; run node scripts/build-fips-kat.mjs')
    process.exit(1)
  }
  console.log('src/fips/kat.js matches the pinned NIST vectors')
} else {
  writeFileSync(OUT, body)
  console.log(`wrote ${OUT}`)
  for (const [k, v] of Object.entries(provenance)) console.log(`  ${k}: ${v}`)
}
