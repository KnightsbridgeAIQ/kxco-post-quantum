// Take a passed test session through the certification step.
//
//   node conformance/acvts/publish.mjs <keepDir> <resourcesFile> [--dry]
//
// The keep directory is the one run-session.mjs wrote, because a session carries
// its OWN access token: the login token returns 403 on a session URL. That token
// is why a session cannot be certified from anywhere but the run artefacts, and
// why --keep is not optional in practice.

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { ACV_VERSION, call, login, payloadOf, refresh } from './client.mjs'

const keepDir = process.argv[2]
const resourcesFile = process.argv[3] ?? 'F:/tmp/acvts/resources.json'
const dry = process.argv.includes('--dry')

if (!keepDir) {
  console.error('usage: publish.mjs <keepDir> <resourcesFile> [--dry]')
  process.exit(2)
}

const session = JSON.parse(readFileSync(join(keepDir, 'session.json'), 'utf8'))
const resources = JSON.parse(readFileSync(resourcesFile, 'utf8'))
let sessionToken = session.accessToken
const url = session.url

await login() // proves the credential is live before anything is changed

// A kept session token is usually stale by the time anyone certifies: the run
// finished hours ago. Renew on a 401 and write the fresh token back, so a second
// attempt does not have to repeat this.
async function authed(path, opts = {}) {
  let r = await call(path, { ...opts, token: sessionToken })
  if (r.status === 401) {
    console.log('session token expired, renewing')
    sessionToken = await refresh(sessionToken)
    session.accessToken = sessionToken
    writeFileSync(join(keepDir, 'session.json'), JSON.stringify(session, null, 2))
    r = await call(path, { ...opts, token: sessionToken })
  }
  return r
}

const read = await authed(url)
if (read.status !== 200) throw new Error(`GET ${url}: HTTP ${read.status} ${read.body.slice(0, 300)}`)
const state = payloadOf(read.body)
console.log(`${url}: passed=${state.passed} publishable=${state.publishable} published=${state.published ?? false}`)

if (state.published) {
  console.log('already certified')
  process.exit(0)
}
if (!state.publishable) {
  console.log('not publishable, nothing to certify')
  process.exit(1)
}

const body = { moduleUrl: resources.module, oeUrl: resources.oe }
console.log(`certifying against module ${body.moduleUrl} and oe ${body.oeUrl}`)

if (dry) {
  console.log(JSON.stringify(body, null, 2))
  process.exit(0)
}

const put = await authed(url, { method: 'PUT', body: [{ acvVersion: ACV_VERSION }, body] })
console.log(`PUT ${url} -> ${put.status}`)
console.log(put.body.slice(0, 1200))

if (put.status >= 400) process.exit(1)

// A certification does not complete on the call. The PUT returns
// /acvp/v1/requests/{id} with status "initial", and NIST approves it out of
// band. Poll the REQUEST, not the session: the session keeps saying
// published=false the whole time, which reads like the certification failed.
const accepted = payloadOf(put.body)
const requestUrl = accepted.url
console.log(`certification request ${requestUrl}, status ${accepted.status}`)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
for (let i = 0; i < 30; i++) {
  const req = payloadOf((await authed(requestUrl)).body)
  if (req.status === 'approved') {
    const s = payloadOf((await authed(url)).body)
    console.log('')
    console.log(`approved: ${req.approvedUrl ?? '(no url)'}`)
    console.log(`published: ${s.published}`)
    console.log(`certificate: ${s.certificateNumber ?? s.validationId ?? '(not reported on the session)'}`)
    process.exit(0)
  }
  if (req.status === 'rejected') {
    console.log(`rejected: ${JSON.stringify(req).slice(0, 600)}`)
    process.exit(1)
  }
  if (i === 0) console.log(`  waiting on NIST approval, status ${req.status}`)
  await sleep(20_000)
}
console.log(`still ${'"initial"'} after 10 minutes. The request is queued with NIST and is`)
console.log(`checked later with: node conformance/acvts/check-request.mjs ${requestUrl.split('/').pop()}`)
