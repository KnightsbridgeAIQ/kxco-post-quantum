// Read the finished state back off the server: the validation, the module it
// covers, and every test session attached to it. Run output is not evidence;
// what the server says afterwards is.
//
//   node conformance/acvts/verify-demo-certificate.mjs <validationId> <sessionId>...

import { call, login, payloadOf } from './client.mjs'

const [validationId, ...sessionIds] = process.argv.slice(2)
if (!validationId) {
  console.error('usage: verify-demo-certificate.mjs <validationId> <sessionId>...')
  process.exit(2)
}

const token = await login()

const v = payloadOf((await call(`/acvp/v1/validations/${validationId}`, { token })).body)
console.log(`validation ${validationId}`)
console.log(`  certificate : ${v.validationId}`)
console.log(`  module      : ${v.moduleUrl}`)
console.log(`  environments: ${(v.oeUrls ?? []).join(', ')}`)

const m = payloadOf((await call(v.moduleUrl, { token })).body)
console.log(`  module name : ${m.name} ${m.version} (${m.type})`)
console.log(`  vendor      : ${m.vendorUrl}`)

for (const oe of v.oeUrls ?? []) {
  const o = payloadOf((await call(oe, { token })).body)
  console.log(`  oe          : ${o.name}`)
}

// A session URL needs the session's own token, not the login token, so this
// reports the HTTP code rather than pretending to read the body. 403 here means
// the session exists and this token is not scoped to it, which is expected.
for (const id of sessionIds) {
  const r = await call(`/acvp/v1/testSessions/${id}`, { token })
  const s = r.body ? payloadOf(r.body) : {}
  const detail = r.status === 200
    ? `passed=${s.passed} publishable=${s.publishable} published=${s.published}`
    : '(needs the session token; see the kept session.json)'
  console.log(`session ${id}: HTTP ${r.status} ${detail}`)
}
