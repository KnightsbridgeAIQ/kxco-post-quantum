// The CBOM has to be a legal CycloneDX 1.6 document, and it has to be true.
//
// Legal is checked against the specification's own schema. The three files
// under test/schema are taken unmodified from the CycloneDX specification
// repository, the same copies kxco-pq-scan validates against.
//
// True is checked against the source. scripts/build-cbom.mjs refuses to build
// if src/ binds an algorithm the CBOM does not declare, or if a declared use is
// gone. Most of this file exists to prove that refusal can actually happen: a
// gate that has never failed is not known to be a gate, so every check below
// has a control that feeds it something wrong and requires a rejection.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import Ajv from 'ajv'
import addFormats from 'ajv-formats'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

import {
  ASSETS, buildCbom, detect, readSources,
} from '../scripts/build-cbom.mjs'

const read = (path) => readFileSync(new URL('../' + path, import.meta.url), 'utf8')
const schema = (name) => JSON.parse(read('test/schema/' + name))

const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
ajv.addSchema(schema('spdx.schema.json'), 'http://cyclonedx.org/schema/spdx.schema.json')
ajv.addSchema(schema('jsf-0.82.schema.json'), 'http://cyclonedx.org/schema/jsf-0.82.schema.json')
const validate = ajv.compile(schema('bom-1.6.schema.json'))
const why = () => (validate.errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message}`).slice(0, 5).join('; ')

const cbom = buildCbom()
const algorithms = cbom.components.filter((c) => c.cryptoProperties?.assetType === 'algorithm')
const byName = (name) => algorithms.find((c) => c.name === name)
const scopeOf = (c) => c.properties.find((p) => p.name === 'kxco:scope').value

// A copy of the real sources with one file's text changed.
function sourcesWith(location, change) {
  return readSources().map((f) => (f.location === location ? { ...f, text: change(f.text) } : f))
}

test('the CBOM validates against the CycloneDX 1.6 schema', () => {
  assert.ok(validate(cbom), why())
  assert.equal(cbom.specVersion, '1.6')
})

test('control: the validator rejects documents that break the schema', () => {
  const broken = [
    { ...cbom, bomFormat: 'SPDX' },
    { ...cbom, serialNumber: 'not-a-urn' },
    { ...cbom, version: 'one' },
    { ...cbom, components: [{ ...algorithms[0], cryptoProperties: { ...algorithms[0].cryptoProperties, assetType: 'magic' } }] },
    { ...cbom, components: [{ ...algorithms[0], cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'quantum-proof' } } }] },
    { ...cbom, components: [{ ...algorithms[0], cryptoProperties: { assetType: 'algorithm', algorithmProperties: { nistQuantumSecurityLevel: 9 } } }] },
  ]
  for (const doc of broken) assert.equal(validate(doc), false, 'a broken document validated')
})

test('every algorithm the package offers is declared, with the parameter sets it exposes', () => {
  const offered = algorithms.filter((c) => scopeOf(c) === 'offered').map((c) => c.name).sort()
  assert.deepEqual(offered, [
    'HKDF-SHA-512', 'HMAC-SHA-256', 'ML-DSA-65', 'ML-DSA-87', 'ML-KEM-1024', 'ML-KEM-768',
    'SHA-256', 'SLH-DSA-SHA2-192s',
  ])
})

test('the classical release layer is in the document, stated as not quantum-safe', () => {
  const pipeline = algorithms.filter((c) => scopeOf(c) === 'release-pipeline')
  assert.deepEqual(pipeline.map((c) => c.name).sort(), ['ECDSA', 'ECDSA P-256'])
  for (const c of pipeline) {
    assert.equal(c.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0, c.name)
  }
  const tls = cbom.components.find((c) => c.cryptoProperties?.assetType === 'protocol')
  assert.equal(tls.cryptoProperties.protocolProperties.type, 'tls')
  // The package does not choose the key exchange, so the document must not claim one.
  assert.equal(JSON.stringify(tls).includes('nistQuantumSecurityLevel'), false)
})

test('the post-quantum OIDs are the ones CONFORMANCE.md reads back out of OpenSSL', () => {
  const table = new Map(
    [...read('CONFORMANCE.md').matchAll(/^\| ((?:ML|SLH)-[A-Z0-9-]+[a-z]?) \| ([0-9.]+) \|$/gm)]
      .map((m) => [m[1], m[2]]))
  const pq = algorithms.filter((c) => /^(ML|SLH)-/.test(c.name))
  assert.equal(pq.length, 9)
  for (const c of pq) assert.equal(c.cryptoProperties.oid, table.get(c.name), c.name)
})

test('key sizes are carried per field, in bits, and match the implementation', () => {
  const material = (alg, type) => cbom.components.find((c) =>
    c.cryptoProperties?.relatedCryptoMaterialProperties?.algorithmRef === byName(alg)['bom-ref'] &&
    c.cryptoProperties.relatedCryptoMaterialProperties.type === type)
  const size = (alg, type) => material(alg, type).cryptoProperties.relatedCryptoMaterialProperties.size
  assert.equal(size('ML-DSA-65', 'public-key'), ml_dsa65.lengths.publicKey * 8)
  assert.equal(size('ML-DSA-65', 'signature'), ml_dsa65.lengths.signature * 8)
  assert.equal(size('ML-KEM-768', 'ciphertext'), ml_kem768.lengths.cipherText * 8)
  assert.equal(size('ML-KEM-768', 'shared-secret'), 256)
  for (const c of algorithms.filter((a) => /^(ML|SLH)-/.test(a.name))) {
    assert.ok(material(c.name, 'public-key'), `${c.name} has no public-key size`)
    assert.ok(material(c.name, 'private-key'), `${c.name} has no private-key size`)
  }
})

test('every occurrence points at a real line of the file it names', () => {
  for (const c of algorithms) {
    for (const o of c.evidence?.occurrences ?? []) {
      const lines = read(o.location).split('\n')
      assert.ok(lines[o.line - 1]?.includes(o.symbol), `${c.name}: ${o.symbol} is not on ${o.location}:${o.line}`)
    }
  }
})

test('the offered algorithms are named in CRYPTO-INVENTORY.md, so the two documents agree', () => {
  const inventory = read('CRYPTO-INVENTORY.md')
  for (const c of algorithms.filter((a) => scopeOf(a) === 'offered')) {
    assert.ok(inventory.includes(c.name), `${c.name} is in the CBOM but not in CRYPTO-INVENTORY.md`)
  }
})

test('the build is byte-identical across runs and backends', () => {
  const env = { ...process.env, SOURCE_DATE_EPOCH: '1790000000' }
  const once = execFileSync(process.execPath, ['scripts/build-cbom.mjs'], { encoding: 'utf8', env })
  const js = execFileSync(process.execPath, ['scripts/build-cbom.mjs'], {
    encoding: 'utf8', env: { ...env, KXCO_PQ_BACKEND: 'javascript' },
  })
  assert.equal(once, js)
  assert.ok(once.includes('"timestamp": "2026-09-21T14:13:20Z"'))
})

// ── the controls: each of these must be refused ────────────────────────────

test('control: an undeclared import from @noble is refused', () => {
  const files = sourcesWith('src/kid.js', (t) => t.replace(
    "import { sha256 } from '@noble/hashes/sha2.js'",
    "import { sha256 } from '@noble/hashes/sha2.js'\nimport { x25519 } from '@noble/curves/ed25519.js'"))
  assert.throws(() => buildCbom({ files }), /undeclared cryptography: x25519 in src\/kid\.js/)
})

test('control: a node:crypto call that names its own algorithm is refused', () => {
  for (const [inject, expect] of [
    ["crypto.createHash('md5')", /crypto\.createHash/],
    ["crypto.randomBytes(32)", /crypto\.randomBytes/],
    ["crypto.generateKeyPairSync('rsa', {})", /crypto\.generateKeyPairSync\('rsa'\)/],
    ["crypto.sign('sha256', m, k)", /crypto\.sign\('sha256'\)/],
  ]) {
    const files = sourcesWith('src/_native.node.js', (t) => t + '\n' + inject + '\n')
    assert.throws(() => buildCbom({ files }), expect, inject)
  }
})

test('control: an algorithm dropped from the declaration is refused', () => {
  const assets = ASSETS.filter((a) => a.name !== 'ML-DSA-44')
  assert.throws(() => buildCbom({ assets }), /undeclared cryptography: nodeName: 'ml-dsa-44'/)
})

test('control: a declared use that is gone from the source is refused', () => {
  const files = sourcesWith('src/derive.js', (t) => t.replace(/hkdf/g, 'kdf'))
  assert.throws(() => buildCbom({ files }), /declared but not in the source: HKDF-SHA-512: hkdf/)
})

test('control: a use mentioned only in a comment does not count as present', () => {
  const files = sourcesWith('src/kid.js', (t) =>
    t.split('\n').map((l) => (l.includes('sha256') ? '// ' + l : l)).join('\n'))
  assert.throws(() => buildCbom({ files }), /declared but not in the source: SHA-256: sha256/)
  // And the other direction: an import written only in a comment is not detected.
  const commented = [{ location: 'src/x.js', text: "// import { x25519 } from '@noble/curves/ed25519.js'\n" }]
  assert.deepEqual(detect(commented), [])
})
