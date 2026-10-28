// Offline gate for responders-fips.mjs: answer NIST's pinned sample files for
// SHA-2, SHA-3, SHAKE, HMAC and HMAC_DRBG with the FIPS module's own code, and
// compare every answer with NIST's expected result, before any of it goes to
// NIST's server. Cases outside the registration (non-whole-byte lengths, large
// data, other DRBG modes) are counted as excluded, by name, not as passes.
//
//   node conformance/acvts/selftest-fips.mjs

import { readFileSync } from 'node:fs'
import { vectorPath } from '../fetch-vectors.mjs'
import { respond, registered } from './responders-fips.mjs'

const SETS = ['SHA2-256-1.0', 'SHA2-512-1.0', 'SHA3-256-2.0', 'SHA3-512-2.0', 'SHAKE-128-FIPS202', 'SHAKE-256-FIPS202', 'HMAC-SHA2-512-2.0', 'hmacDRBG-1.0']
const load = (set, f) => { const j = JSON.parse(readFileSync(vectorPath(set, f), 'utf8')); return Array.isArray(j) ? j[1] : j }
const norm = (v) => JSON.stringify(v).toUpperCase()

let failed = 0
for (const set of SETS) {
  const prompt = load(set, 'prompt')
  const want = new Map()
  for (const g of load(set, 'expectedResults').testGroups) for (const t of g.tests) want.set(t.tcId, t)
  let matched = 0, mismatched = 0, excluded = 0
  for (const g of prompt.testGroups) {
    const tests = g.tests.filter((t) => registered(prompt, g, t))
    excluded += g.tests.length - tests.length
    if (!tests.length) continue
    const answer = respond({ ...prompt, testGroups: [{ ...g, tests }] })
    for (const t of answer.testGroups[0].tests) {
      const w = want.get(t.tcId)
      const bad = Object.entries(t).some(([k, v]) => k !== 'tcId' && norm(v) !== norm(w[k]))
      if (bad) { mismatched++; if (mismatched <= 3) console.log(`  MISMATCH ${set} tgId ${g.tgId} tcId ${t.tcId}`) } else matched++
    }
  }
  failed += mismatched
  console.log(`${set.padEnd(20)} matched ${String(matched).padStart(5)}  mismatched ${mismatched}  excluded by registration ${excluded}`)
}
console.log(failed ? `\n${failed} mismatch(es): do not send this responder to NIST` : '\nevery registered case matches NIST\'s expected results')
process.exit(failed ? 1 : 0)
