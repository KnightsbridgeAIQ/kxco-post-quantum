// Print a validation record. This is the demo certificate: its number is what
// NIST wants quoted when Production access is requested.
//
//   node conformance/acvts/show-validation.mjs <id> [<id>...]

import { call, login } from './client.mjs'

const ids = process.argv.slice(2)
if (ids.length === 0) {
  console.error('usage: show-validation.mjs <id> [<id>...]')
  process.exit(2)
}

const token = await login()

for (const id of ids) {
  const r = await call(`/acvp/v1/validations/${id}`, { token })
  console.log(`--- validation ${id}: HTTP ${r.status}`)
  console.log(r.body.slice(0, 2500))
}
