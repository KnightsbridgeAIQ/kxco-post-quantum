// Gate: prove the live-protocol responder produces exactly the answers NIST
// already published, before any of it is sent to NIST's server.
//
// The responder is new code on an old, verified computation. This runs it
// against the pinned ACVP-Server vector files, which carry expected results, and
// compares field by field. A group the backend refuses is reported by name,
// because that list is what the live registration must exclude.
//
//   node conformance/acvts/selftest.mjs [--set NAME[,NAME...]] [--json PATH]

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { respond } from './responders.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE = join(HERE, '..', '.acvp-cache', 'gen-val', 'json-files')

const SETS = [
  'ML-KEM-keyGen-FIPS203',
  'ML-KEM-encapDecap-FIPS203',
  'ML-DSA-keyGen-FIPS204',
  'ML-DSA-sigGen-FIPS204',
  'ML-DSA-sigVer-FIPS204',
  'SLH-DSA-keyGen-FIPS205',
  'SLH-DSA-sigGen-FIPS205',
  'SLH-DSA-sigVer-FIPS205',
]

const args = process.argv.slice(2)
const only = args.includes('--set')
  ? args[args.indexOf('--set') + 1].split(',').map((s) => s.trim()).filter(Boolean)
  : SETS
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null

// Compare only the fields the response actually carries. NIST's expected
// results may hold more; extra fields there are not our concern.
function compare(got, want) {
  for (const [k, v] of Object.entries(got)) {
    if (k === 'tcId') continue
    if (!(k in want)) return `expected results carry no ${k}`
    const a = typeof v === 'string' ? v.toUpperCase() : v
    const b = typeof want[k] === 'string' ? want[k].toUpperCase() : want[k]
    if (a !== b) return `${k} mismatch`
  }
  return null
}

const report = { sets: [], totals: { matched: 0, mismatched: 0, refused: 0 } }
let failed = 0

for (const set of only) {
  const prompt = JSON.parse(readFileSync(join(CACHE, set, 'prompt.json'), 'utf8'))
  const expected = JSON.parse(readFileSync(join(CACHE, set, 'expectedResults.json'), 'utf8'))

  const wantById = new Map()
  for (const g of expected.testGroups) {
    for (const t of g.tests) wantById.set(`${g.tgId}:${t.tcId}`, t)
  }

  const row = { set, matched: 0, mismatched: 0, refused: 0, refusals: [], mismatches: [] }

  // One group at a time, so a group the backend refuses names itself instead of
  // taking the whole set down with it.
  for (const g of prompt.testGroups) {
    let out
    try {
      out = respond({ ...prompt, testGroups: [g] })
    } catch (err) {
      row.refused += g.tests.length
      row.refusals.push({ tgId: g.tgId, parameterSet: g.parameterSet, hashAlg: g.hashAlg, reason: err.message })
      continue
    }
    for (const rg of out.testGroups) {
      for (const t of rg.tests) {
        const want = wantById.get(`${rg.tgId}:${t.tcId}`)
        if (!want) {
          row.mismatched++
          row.mismatches.push({ tgId: rg.tgId, tcId: t.tcId, detail: 'no expected result' })
          continue
        }
        const problem = compare(t, want)
        if (problem) {
          row.mismatched++
          if (row.mismatches.length < 10) row.mismatches.push({ tgId: rg.tgId, tcId: t.tcId, detail: problem })
        } else {
          row.matched++
        }
      }
    }
  }

  const verdict = row.mismatched === 0 ? 'MATCH' : 'MISMATCH'
  if (row.mismatched > 0) failed = 1
  console.log(
    `${verdict.padEnd(9)} ${set.padEnd(30)} ${String(row.matched).padStart(5)} matched  ` +
      `${String(row.mismatched).padStart(3)} mismatched  ${String(row.refused).padStart(4)} refused`,
  )
  for (const r of row.refusals.slice(0, 6)) {
    console.log(`            refused tgId ${r.tgId} ${r.parameterSet}: ${r.reason}`)
  }
  for (const m of row.mismatches.slice(0, 6)) {
    console.log(`            tgId ${m.tgId} tcId ${m.tcId}: ${m.detail}`)
  }

  report.sets.push(row)
  report.totals.matched += row.matched
  report.totals.mismatched += row.mismatched
  report.totals.refused += row.refused
}

const t = report.totals
console.log(`\n${t.matched} matched, ${t.mismatched} mismatched, ${t.refused} refused`)

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, JSON.stringify(report, null, 2))
  console.log(`report written to ${jsonOut}`)
}

process.exit(failed)
