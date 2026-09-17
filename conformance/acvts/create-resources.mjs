// Create the vendor, contact, operational environment and module records a
// test session must point at before NIST will certify it.
//
//   node conformance/acvts/create-resources.mjs <stateFile>
//
// Idempotent: every URL it creates is written to the state file, and a re-run
// reuses what is already there rather than minting a second copy. Duplicated
// vendor records are the standard mess on this database and they are ours to
// avoid.
//
// Resource creation is ASYNCHRONOUS. A POST returns /acvp/v1/requests/{id},
// not the resource, and the request has to be polled until the server approves
// it. Reading the POST body as if it were the created record is the trap.
//
// Every fact below is one NIST already holds: the company as it appears on the
// UK register, the contact address on the certificate they issued, and the
// machine the vectors were actually computed on. Nothing here asserts anything
// new about the firm.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'

import { ACV_VERSION, call, login, payloadOf } from './client.mjs'

const stateFile = process.argv[2] ?? 'F:/tmp/acvts/resources.json'
const state = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : {}
const save = () => writeFileSync(stateFile, JSON.stringify(state, null, 2))

const token = await login()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// POST a resource and follow the request through to the approved URL.
async function create(kind, path, body) {
  if (state[kind]) {
    console.log(`${kind}: already ${state[kind]}`)
    return state[kind]
  }

  const r = await call(path, { method: 'POST', body: [{ acvVersion: ACV_VERSION }, body], token })
  if (r.status >= 400) throw new Error(`${kind}: HTTP ${r.status} ${r.body.slice(0, 400)}`)
  const accepted = payloadOf(r.body)

  // Some deployments return the resource directly; most return a request URL.
  let url = accepted.url
  if (url && url.includes('/requests/')) {
    for (let i = 0; i < 60; i++) {
      const q = await call(url, { token })
      const req = payloadOf(q.body)
      if (req.status === 'approved') {
        url = req.approvedUrl ?? req.url
        break
      }
      if (req.status === 'rejected') throw new Error(`${kind}: request rejected ${q.body.slice(0, 300)}`)
      await sleep(5000)
    }
  }
  if (!url || url.includes('/requests/')) throw new Error(`${kind}: request never approved`)

  state[kind] = url
  save()
  console.log(`${kind}: created ${url}`)
  return url
}

// ------------------------------------------------------------------- records

const vendorUrl = await create('vendor', '/acvp/v1/vendors', {
  name: 'Knightsbridge Financial Ltd',
  website: 'https://kxco.ai',
  emails: ['shayne@knightsbridgelaw.com'],
  addresses: [
    {
      street1: '71-75 Shelton Street',
      street2: 'Covent Garden',
      locality: 'London',
      country: 'GB',
      postalCode: 'WC2H 9JQ',
    },
  ],
})

// The address the vendor record minted, which the module has to point at.
if (!state.addressUrl) {
  const v = payloadOf((await call(vendorUrl, { token })).body)
  state.addressUrl = v.addresses?.[0]?.url
  save()
  console.log(`address: ${state.addressUrl}`)
}

const personUrl = await create('person', '/acvp/v1/persons', {
  fullName: 'Shayne Heffernan',
  vendorUrl,
  emails: ['shayne@knightsbridgelaw.com'],
})

// Two dependencies: what it ran on, and what it ran on top of.
const osUrl = await create('dependency-os', '/acvp/v1/dependencies', {
  type: 'software',
  name: 'Windows 10 Pro 22H2 (build 19045) with Node.js 26.1.0',
  description: 'The operating system and JavaScript runtime the vectors were computed on.',
})

const cpuUrl = await create('dependency-cpu', '/acvp/v1/dependencies', {
  type: 'processor',
  name: 'Intel Core i7-7700K',
  description: 'x86-64, no cryptographic acceleration used by this implementation.',
})

const oeUrl = await create('oe', '/acvp/v1/oes', {
  name: 'Node.js 26.1.0 on Windows 10 Pro 22H2, Intel Core i7-7700K',
  dependencyUrls: [osUrl, cpuUrl],
})

const moduleUrl = await create('module', '/acvp/v1/modules', {
  name: 'kxco-post-quantum',
  version: '1.7.2',
  type: 'Software',
  vendorUrl,
  addressUrl: state.addressUrl,
  contactUrls: [personUrl],
  description:
    'JavaScript library providing FIPS 203 ML-KEM, FIPS 204 ML-DSA and FIPS 205 SLH-DSA. ' +
    'The post-quantum primitives under test are @noble/post-quantum 0.7.0 as built and ' +
    'distributed in this package. Algorithm testing covers those primitives directly.',
})

console.log('')
console.log('module', moduleUrl)
console.log('oe    ', oeUrl)
console.log(`state written to ${stateFile}`)
