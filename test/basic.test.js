import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import {
  mlDsa, mlKem, deriveSeed, fingerprint, kidEquals, webhook,
} from '../src/index.js'

test('deriveSeed is deterministic and domain-separated', () => {
  const master = Buffer.from('00'.repeat(32), 'hex')
  const a = deriveSeed(master, 'role-a', 32)
  const b = deriveSeed(master, 'role-a', 32)
  const c = deriveSeed(master, 'role-b', 32)
  assert.deepEqual(a, b, 'same input yields same seed')
  assert.notDeepEqual(a, c, 'different info yields different seed')
})

test('ML-DSA-65 sign + verify round trip', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const sig = mlDsa.sign(secretKey, 'hello kxco')
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 6618, 'ML-DSA-65 sig = 3309 bytes = 6618 hex chars')
  assert.ok(mlDsa.verify(publicKey, 'hello kxco', sig))
  assert.ok(!mlDsa.verify(publicKey, 'tampered', sig))
})

test('ML-DSA keypair is deterministic from master', () => {
  const master = Buffer.from('11'.repeat(32), 'hex')
  const a = mlDsa.keypairFromMaster(master, 'platform-v1')
  const b = mlDsa.keypairFromMaster(master, 'platform-v1')
  assert.deepEqual(a.publicKey, b.publicKey)
})

test('ML-KEM-768 encapsulate + decapsulate', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlKem.keypairFromMaster(master)
  const { ciphertext, sharedSecret } = mlKem.encapsulate(publicKey)
  const recovered = mlKem.decapsulate(ciphertext, secretKey)
  assert.deepEqual(sharedSecret, recovered)
  assert.equal(sharedSecret.length, 32)
})

test('fingerprint is stable 16 hex chars', () => {
  const master = randomBytes(32)
  const { publicKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  assert.equal(kid.length, 16)
  assert.match(kid, /^[0-9a-f]{16}$/)
  assert.equal(fingerprint(publicKey), kid)
})

test('kidEquals is constant-time string compare', () => {
  assert.ok(kidEquals('4a7c9e2f1b3d5680', '4a7c9e2f1b3d5680'))
  assert.ok(!kidEquals('4a7c9e2f1b3d5680', '0000000000000000'))
  assert.ok(!kidEquals('4a7c9e2f1b3d5680', 'short'))
})

test('webhook hybrid signing round trip', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  const hmacSecret = 'shared-secret-bytes'
  const rawBody = JSON.stringify({ event: 'payment.settled', amount: 1000 })

  const headers = webhook.signDelivery({
    rawBody, hmacSecret, pqSecretKey: secretKey, pqKid: kid, event: 'payment.settled',
  })

  assert.ok(headers['X-KXCO-Timestamp'])
  assert.ok(headers['X-KXCO-Signature'].startsWith('sha256='))
  assert.ok(headers['X-KXCO-PQ-Signature'].startsWith('ml-dsa-65='))
  assert.equal(headers['X-KXCO-PQ-Kid'], kid)

  const receiverHeaders = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  )
  const result = webhook.verifyDelivery({
    headers: receiverHeaders, rawBody, hmacSecret, pqPublicKey: publicKey, pinnedKid: kid,
  })

  assert.ok(result.timestampOk)
  assert.ok(result.kidOk)
  assert.ok(result.hmacOk)
  assert.ok(result.pqOk)
})

test('webhook verify rejects tampered body', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  const secret = 's'
  const headers = webhook.signDelivery({
    rawBody: 'original', hmacSecret: secret, pqSecretKey: secretKey, pqKid: kid,
  })
  const lowered = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  const result = webhook.verifyDelivery({
    headers: lowered, rawBody: 'tampered', hmacSecret: secret, pqPublicKey: publicKey, pinnedKid: kid,
  })
  assert.ok(!result.hmacOk)
  assert.ok(!result.pqOk)
})

test('webhook verify rejects stale timestamp', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  // Manually construct headers with a stale timestamp
  const oldTs = String(Math.floor(Date.now() / 1000) - 3600)
  const body = 'x'
  const headers = {
    'x-kxco-timestamp':    oldTs,
    'x-kxco-signature':    'sha256=' + webhook.hmacHex('s', oldTs, body),
    'x-kxco-pq-signature': webhook.pqSign(secretKey, oldTs, body),
    'x-kxco-pq-kid':       kid,
  }
  const result = webhook.verifyDelivery({
    headers, rawBody: body, hmacSecret: 's', pqPublicKey: publicKey, pinnedKid: kid,
  })
  assert.ok(!result.timestampOk)
  assert.ok(!result.hmacOk)
  assert.ok(!result.pqOk)
})
