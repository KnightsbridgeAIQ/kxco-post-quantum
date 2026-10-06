// The ml-dsa-87= webhook header form, beside ml-dsa-65=.
//
// The key decides the form: an ML-DSA-87 key signs `ml-dsa-87=<hex>` and
// verifies only that, and an ML-DSA-65 key signs and verifies `ml-dsa-65=`
// exactly as before, bare hex included. A header whose prefix names the other
// set fails. A delivery signed by 1.7.9, before the -87 form, still verifies.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87, webhook } from '../src/index.js'

const k65 = mlDsa.ml_dsa65.keygen()
const k87 = mlDsa87.ml_dsa87.keygen()
const ts = '1790000000'
const body = '{"event":"payment.settled"}'

test('an ML-DSA-87 key signs the ml-dsa-87= header form, and it verifies with that key', () => {
  const header = webhook.pqSign(k87.secretKey, ts, body)
  assert.match(header, /^ml-dsa-87=[0-9a-f]{9254}$/)
  assert.equal(webhook.verifyPq(k87.publicKey, ts, body, header), true)
  assert.equal(webhook.verifyPq(k87.publicKey, ts, body + ' ', header), false)
  assert.equal(webhook.verifyPq(mlDsa87.ml_dsa87.keygen().publicKey, ts, body, header), false)
})

test('an ML-DSA-65 key still signs ml-dsa-65=, and verifies it with or without the prefix', () => {
  const header = webhook.pqSign(k65.secretKey, ts, body)
  assert.match(header, /^ml-dsa-65=[0-9a-f]{6618}$/)
  assert.equal(webhook.verifyPq(k65.publicKey, ts, body, header), true)
  assert.equal(webhook.verifyPq(k65.publicKey, ts, body, header.slice('ml-dsa-65='.length)), true)
})

test('the prefix must match the key: a header naming the other set fails, and so does a bare -87 value', () => {
  const h65 = webhook.pqSign(k65.secretKey, ts, body)
  const h87 = webhook.pqSign(k87.secretKey, ts, body)
  const hex65 = h65.slice('ml-dsa-65='.length)
  const hex87 = h87.slice('ml-dsa-87='.length)
  // A genuine signature under the right key, but with the other set's prefix.
  assert.equal(webhook.verifyPq(k87.publicKey, ts, body, `ml-dsa-65=${hex87}`), false)
  assert.equal(webhook.verifyPq(k65.publicKey, ts, body, `ml-dsa-87=${hex65}`), false)
  // ML-DSA-87 has no bare-hex legacy form.
  assert.equal(webhook.verifyPq(k87.publicKey, ts, body, hex87), false)
  // And a key of one set never verifies the other set's header.
  assert.equal(webhook.verifyPq(k65.publicKey, ts, body, h87), false)
  assert.equal(webhook.verifyPq(k87.publicKey, ts, body, h65), false)
})

test('signDelivery and verifyDelivery carry an ML-DSA-87 key end to end', () => {
  const headers = webhook.signDelivery({
    rawBody: body, hmacSecret: 's', pqSecretKey: k87.secretKey, pqKid: 'k87', event: 'payment.settled',
  })
  assert.ok(headers['X-KXCO-PQ-Signature'].startsWith('ml-dsa-87='))
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  const ok = webhook.verifyDelivery({ headers: lower, rawBody: body, hmacSecret: 's', pqPublicKey: k87.publicKey, pinnedKid: 'k87' })
  assert.deepEqual(ok, { hmacOk: true, pqOk: true, timestampOk: true, kidOk: true })
  const wrongSet = webhook.verifyDelivery({ headers: lower, rawBody: body, pqPublicKey: k65.publicKey, pinnedKid: 'k87' })
  assert.equal(wrongSet.pqOk, false)
})

test('a delivery signed by 1.7.9, before the ml-dsa-87= form, verifies unchanged', () => {
  const f = JSON.parse(readFileSync(new URL('./fixtures/webhook-1.7.9.json', import.meta.url), 'utf8'))
  const publicKey = Buffer.from(f.publicKey, 'hex')
  assert.ok(f.pqSignature.startsWith('ml-dsa-65='))
  assert.equal(webhook.verifyPq(publicKey, f.timestamp, f.rawBody, f.pqSignature), true)
  assert.equal(webhook.verifyPq(publicKey, f.timestamp, f.rawBody, f.pqSignature.slice('ml-dsa-65='.length)), true)
  assert.equal(webhook.verifyHmac(f.hmacSecret, f.timestamp, f.rawBody, f.hmacSignature), true)
  assert.equal(webhook.verifyPq(publicKey, f.timestamp, f.rawBody + 'x', f.pqSignature), false)
})
