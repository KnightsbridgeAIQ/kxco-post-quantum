// Run a live ACVP test session against the NIST ACVTS Demo server.
//
//   node conformance/acvts/run-session.mjs <name>[,<name>...] [--sample] [--keep DIR] [--resume]
//
// Names come from registrations.mjs, e.g. ml-kem-keygen.
//
// --sample asks NIST to include the expected answers with the prompt. Use it to
// prove the loop, never to claim a result: a sample session is a rehearsal.
//
// Nothing here writes a credential anywhere. Prompts and responses are kept
// only if --keep is given, and they belong outside the repository.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { ACV_VERSION, call, login, payloadOf, refresh } from './client.mjs'
import { respond } from './responders.mjs'
import { REGISTRATIONS } from './registrations.mjs'

const args = process.argv.slice(2)
const names = (args[0] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
const isSample = args.includes('--sample')
const keepDir = args.includes('--keep') ? args[args.indexOf('--keep') + 1] : null
// --resume picks up a kept run: the same session, and any answer already
// computed is submitted from disk rather than recomputed. SLH-DSA signing costs
// an hour, so recomputing it because a token expired is not acceptable.
const resume = args.includes('--resume')

if (names.length === 0) {
  console.error('usage: run-session.mjs <name>[,<name>...] [--sample] [--keep DIR] [--resume]')
  console.error('names: ' + Object.keys(REGISTRATIONS).join(', '))
  process.exit(2)
}

const algorithms = names.map((n) => {
  const reg = REGISTRATIONS[n]
  if (!reg) throw new Error(`unknown registration: ${n}`)
  return reg
})

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const keep = (name, data) => {
  if (!keepDir) return
  mkdirSync(keepDir, { recursive: true })
  writeFileSync(join(keepDir, name), JSON.stringify(data, null, 2))
}

function ok(r, what) {
  if (r.status >= 200 && r.status < 300) return payloadOf(r.body)
  throw new Error(`${what}: HTTP ${r.status} ${r.body.slice(0, 500)}`)
}

const token = await login()
console.log('logged in to demo.acvts.nist.gov')

// ------------------------------------------------------------------- register

let session
if (resume) {
  if (!keepDir) throw new Error('--resume needs --keep pointing at the kept run')
  session = JSON.parse(readFileSync(join(keepDir, 'session.json'), 'utf8'))
  console.log(`resuming ${session.url}`)
} else {
  const registration = [{ acvVersion: ACV_VERSION }, { isSample, algorithms }]
  keep('registration.json', registration)
  session = ok(
    await call('/acvp/v1/testSessions', { method: 'POST', body: registration, token }),
    'register',
  )
  keep('session.json', session)
}

const sessionUrl = session.url
let sessionToken = session.accessToken ?? token
console.log(`session ${sessionUrl}  isSample=${session.isSample}  vectorSets=${session.vectorSetUrls.length}`)

// Any session call may meet an expired JWT. Renew once and repeat rather than
// failing the run.
async function authed(path, opts = {}) {
  let r = await call(path, { ...opts, token: sessionToken })
  if (r.status === 401) {
    console.log('  session token expired, renewing')
    sessionToken = await refresh(sessionToken)
    session.accessToken = sessionToken
    keep('session.json', session)
    r = await call(path, { ...opts, token: sessionToken })
  }
  return r
}

// --------------------------------------------------------------- vector sets

const results = []

for (const vsUrl of session.vectorSetUrls) {
  // The prompt is not ready the instant the session is created. The server
  // answers 200 with {"status":"pending"} until the generator has run.
  let prompt
  for (let i = 0; i < 60; i++) {
    const r = await authed(vsUrl)
    const body = payloadOf(r.body)
    if (r.status === 200 && body.testGroups) {
      prompt = body
      break
    }
    if (r.status >= 400) throw new Error(`fetch ${vsUrl}: HTTP ${r.status} ${r.body.slice(0, 300)}`)
    process.stdout.write(`  ${vsUrl}: ${body.status ?? 'not ready'}, waiting\n`)
    await sleep(10_000)
  }
  if (!prompt) throw new Error(`${vsUrl}: prompt never became available`)

  const label = `${prompt.algorithm}-${prompt.mode}-vs${prompt.vsId}`
  const cases = prompt.testGroups.reduce((n, g) => n + g.tests.length, 0)
  console.log(`  ${label}: ${prompt.testGroups.length} groups, ${cases} cases`)
  keep(`${label}-prompt.json`, prompt)

  // On a resumed run, an answer already on disk is the same answer: these
  // computations are deterministic given the prompt. Recomputing it would cost
  // an hour of SLH-DSA signing to produce identical bytes.
  const saved = keepDir ? join(keepDir, `${label}-response.json`) : null
  let answer
  let ms = 0
  if (resume && saved && existsSync(saved)) {
    answer = JSON.parse(readFileSync(saved, 'utf8'))
    console.log(`  ${label}: reusing the kept answer`)
  } else {
    const started = Date.now()
    answer = respond(prompt)
    ms = Date.now() - started
    keep(`${label}-response.json`, answer)
  }

  const post = await authed(`${vsUrl}/results`, {
    method: 'POST',
    body: [{ acvVersion: ACV_VERSION }, answer],
  })
  ok(post, `submit ${label}`)
  console.log(`  ${label}: ${ms ? `answered in ${ms} ms, ` : ''}submitted`)

  // ------------------------------------------------------------ disposition
  let disposition
  for (let i = 0; i < 90; i++) {
    const r = await authed(`${vsUrl}/results`)
    const body = payloadOf(r.body)
    if (body.disposition && body.disposition !== 'incomplete') {
      disposition = body
      break
    }
    await sleep(10_000)
  }
  if (!disposition) throw new Error(`${label}: no disposition after 15 minutes`)

  keep(`${label}-disposition.json`, disposition)
  const bad = (disposition.tests ?? []).filter((t) => t.result !== 'passed')
  console.log(`  ${label}: ${disposition.disposition}${bad.length ? `, ${bad.length} failing cases` : ''}`)
  for (const t of bad.slice(0, 10)) console.log(`      tcId ${t.tcId}: ${t.result}`)

  results.push({ label, vsUrl, disposition: disposition.disposition, failing: bad.length })
}

// ----------------------------------------------------------------- the verdict

const final = ok(await authed(sessionUrl), 'read session')
keep('session-final.json', final)

console.log('')
for (const r of results) console.log(`${r.disposition.padEnd(10)} ${r.label}`)
console.log(`session ${sessionUrl}: passed=${final.passed} publishable=${final.publishable}`)

process.exit(results.every((r) => r.disposition === 'passed') ? 0 : 1)
