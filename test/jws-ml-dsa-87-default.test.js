// signJws takes its default from the key, and the default is ML-DSA-87.
//
// Without opts.alg a 4032-byte ML-DSA-65 secret key signs ML-DSA-65, as it
// always has, and every other key signs ML-DSA-87. An ML-DSA-87 key used to
// need alg named. Tokens signed by 1.8.0, under the old default, still verify,
// which a fixture tests.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87, jws, fingerprint } from '../src/index.js'

const { signJws, verifyJws, decodeJwsHeader } = jws
const MASTER = Buffer.alloc(32, 0x5d)
const k65 = mlDsa.keypairFromMaster(MASTER, 'jws-default-65-v1')
const k87 = mlDsa87.keypairFromMaster(MASTER, 'jws-default-87-v1')

const asArrayBuffer = (key) => key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength)

test('an ML-DSA-87 key with no alg signs ML-DSA-87, and the token verifies under that key', () => {
  const token = signJws({ a: 1 }, k87.secretKey, { kid: fingerprint(k87.publicKey) })
  assert.equal(decodeJwsHeader(token).alg, 'ML-DSA-87')
  const result = verifyJws(token, k87.publicKey, { alg: 'ML-DSA-87' })
  assert.equal(result.valid, true)
  assert.deepEqual(JSON.parse(result.text), { a: 1 })
  assert.match(verifyJws(token, k65.publicKey).error, /but ML-DSA-87 public keys are 2592/)
})

test('an ML-DSA-65 key with no alg still signs ML-DSA-65: the key decides, not the default', () => {
  const token = signJws({ a: 1 }, k65.secretKey)
  assert.equal(decodeJwsHeader(token).alg, 'ML-DSA-65')
  assert.equal(verifyJws(token, k65.publicKey, { alg: 'ML-DSA-65' }).valid, true)
})

test('an explicit alg is used as given, for either set', () => {
  const t65 = signJws({ a: 1 }, k65.secretKey, { alg: 'ML-DSA-65' })
  const t87 = signJws({ a: 1 }, k87.secretKey, { alg: 'ML-DSA-87' })
  assert.equal(decodeJwsHeader(t65).alg, 'ML-DSA-65')
  assert.equal(decodeJwsHeader(t87).alg, 'ML-DSA-87')
  assert.equal(verifyJws(t65, k65.publicKey).valid, true)
  assert.equal(verifyJws(t87, k87.publicKey).valid, true)
})

// The JavaScript primitive names the key length it expected when it refuses a
// key, which says which set signJws chose. The OpenSSL one does not.
const expectedLength = (err) => Number(/expected Uint8Array of length (\d+)/.exec(err.message)?.[1])

test('the key is measured by its byte length, so a key held as an ArrayBuffer decides too', () => {
  // OpenSSL signs with an ArrayBuffer key, and the JavaScript backend refuses
  // one. Either way the set chosen is the key's own.
  for (const [kp, alg, size] of [[k65, 'ML-DSA-65', 4032], [k87, 'ML-DSA-87', 4896]]) {
    let token
    try {
      token = signJws({ a: 1 }, asArrayBuffer(kp.secretKey))
    } catch (err) {
      assert.equal(expectedLength(err), size, alg)
      continue
    }
    assert.equal(decodeJwsHeader(token).alg, alg)
    assert.equal(verifyJws(token, kp.publicKey).valid, true, alg)
  }
})

test('a secret key of neither size is tried as ML-DSA-87 and refused, never signed as ML-DSA-65', () => {
  for (const bad of [new Uint8Array(32), new Uint8Array(4031), new Uint8Array(4897)]) {
    assert.throws(() => signJws({ a: 1 }, bad), (err) => {
      const expected = expectedLength(err)
      return Number.isNaN(expected) || expected === 4896
    }, `${bad.length} bytes`)
  }
})

test('tokens signed by 1.8.0, under the old default, still verify', () => {
  const f = JSON.parse(readFileSync(new URL('./fixtures/jws-1.8.0.json', import.meta.url), 'utf8'))
  for (const alg of ['ML-DSA-65', 'ML-DSA-87']) {
    const { token, publicKey, kid } = f[alg]
    const result = verifyJws(token, Buffer.from(publicKey, 'hex'), { alg, kid })
    assert.equal(result.valid, true, alg)
    assert.deepEqual(JSON.parse(result.text), f.payload, alg)
    assert.equal(result.header.alg, alg)
  }
  // And the fixture's ML-DSA-65 token fails under the ML-DSA-87 key, so the
  // passes above are not a verifier that accepts anything.
  const wrong = verifyJws(f['ML-DSA-65'].token, Buffer.from(f['ML-DSA-87'].publicKey, 'hex'))
  assert.equal(wrong.valid, false)
})
