// Check where a queued request stands. Resource creation and certification both
// return /acvp/v1/requests/{id}, and NIST approves them out of band.
//
//   node conformance/acvts/check-request.mjs <id> [<id>...]

import { call, login, payloadOf } from './client.mjs'

const ids = process.argv.slice(2)
if (ids.length === 0) {
  console.error('usage: check-request.mjs <id> [<id>...]')
  process.exit(2)
}

const token = await login()

for (const id of ids) {
  const r = await call(`/acvp/v1/requests/${id}`, { token })
  const req = payloadOf(r.body)
  console.log(`request ${id}: HTTP ${r.status} status=${req.status ?? '?'} ${req.approvedUrl ?? ''}`)
  if (r.status >= 400 || !req.status) console.log(`  ${r.body.slice(0, 300)}`)
}
