import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import {
  mlDsa, mlDsa87, mlKem, slhDsa, deriveSeed, fingerprint, kidEquals, webhook,
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

test('SLH-DSA-SHA2-192s sign + verify round trip', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = slhDsa.keypairFromMaster(master)
  assert.equal(publicKey.length, 48, 'SLH-DSA-192s public key = 48 bytes')
  assert.equal(secretKey.length, 96, 'SLH-DSA-192s secret key = 96 bytes')
  const sig = slhDsa.sign(secretKey, 'hello kxco')
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 32448, 'SLH-DSA-192s sig = 16224 bytes = 32448 hex chars')
  assert.ok(slhDsa.verify(publicKey, 'hello kxco', sig))
  assert.ok(!slhDsa.verify(publicKey, 'tampered', sig))
})

test('SLH-DSA keypair is deterministic from master', () => {
  const master = Buffer.from('22'.repeat(32), 'hex')
  const a = slhDsa.keypairFromMaster(master, 'platform-v1')
  const b = slhDsa.keypairFromMaster(master, 'platform-v1')
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

// parseInt reads a prefix, so '+a', ' a' and 'a ' would all decode to 0x0a.
// Each byte has one accepted spelling: two hex digits.
test('a signature or key in hex with anything but hex digits is refused', () => {
  const respell = (hex) => {
    for (let i = 0; i < hex.length; i += 2) {
      if (hex[i] === '0') return hex.slice(0, i) + '+' + hex.slice(i + 1)
    }
    throw new Error('no byte below 0x10 to respell')
  }
  for (const [name, scheme] of [['ML-DSA-65', mlDsa], ['ML-DSA-87', mlDsa87], ['SLH-DSA', slhDsa]]) {
    const { publicKey, secretKey } = scheme.keypairFromMaster(Buffer.alloc(32, 7))
    const sig = scheme.sign(secretKey, 'hex spelling')
    assert.ok(scheme.verify(publicKey, 'hex spelling', sig), name)
    assert.equal(scheme.verify(publicKey, 'hex spelling', respell(sig)), false, name)
    assert.equal(scheme.verify(publicKey, 'hex spelling', sig.slice(0, -2) + 'zz'), false, name)
  }

  const { publicKey } = mlDsa.keypairFromMaster(Buffer.alloc(32, 7))
  const pkHex = Buffer.from(publicKey).toString('hex')
  assert.equal(fingerprint(pkHex), fingerprint(publicKey))
  assert.throws(() => fingerprint(respell(pkHex)), /hex/)
  assert.throws(() => fingerprint(pkHex.slice(0, -2) + ' a'), /hex/)
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

// Both signatures cover the timestamp header exactly as it arrives, so the
// header is accepted only as the decimal digits the contract specifies.
test('webhook verify refuses a timestamp header that is not all digits', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  const now = String(Math.floor(Date.now() / 1000))

  // Signed normally, then delivered with the start of the body, up to a '.',
  // moved into the timestamp header.
  const body = '{"amount":"12.50","to":"acct_1"}'
  const moved = webhook.verifyDelivery({
    headers: {
      'x-kxco-timestamp':    `${now}.{"amount":"12`,
      'x-kxco-signature':    'sha256=' + webhook.hmacHex('s', now, body),
      'x-kxco-pq-signature': webhook.pqSign(secretKey, now, body),
      'x-kxco-pq-kid':       kid,
    },
    rawBody: '50","to":"acct_1"}', hmacSecret: 's', pqPublicKey: publicKey, pinnedKid: kid,
  })
  assert.ok(!moved.timestampOk)
  assert.ok(!moved.hmacOk)
  assert.ok(!moved.pqOk)

  // A header that is not all digits is refused even when both signatures
  // cover it exactly.
  for (const ts of [`${now}.x`, `${now}.0`, `${now}e0`, `${now} `, ` ${now}`, `+${now}`, '']) {
    const result = webhook.verifyDelivery({
      headers: {
        'x-kxco-timestamp':    ts,
        'x-kxco-signature':    'sha256=' + webhook.hmacHex('s', ts, 'x'),
        'x-kxco-pq-signature': webhook.pqSign(secretKey, ts, 'x'),
        'x-kxco-pq-kid':       kid,
      },
      rawBody: 'x', hmacSecret: 's', pqPublicKey: publicKey, pinnedKid: kid,
    })
    assert.ok(!result.timestampOk, JSON.stringify(ts))
    assert.ok(!result.hmacOk, JSON.stringify(ts))
    assert.ok(!result.pqOk, JSON.stringify(ts))
  }
})

// Some frameworks hand a repeated header over as an array. Each header is read
// only as a string, so any other type fails the checks that depend on it, and
// the rest of the delivery still verifies.
test('webhook verify reports a header that is not a string without throwing', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  const signed = Object.fromEntries(Object.entries(webhook.signDelivery({
    rawBody: 'x', hmacSecret: 's', pqSecretKey: secretKey, pqKid: kid,
  })).map(([k, v]) => [k.toLowerCase(), v]))

  const fails = {
    'x-kxco-timestamp':    ['timestampOk', 'hmacOk', 'pqOk'],
    'x-kxco-signature':    ['hmacOk'],
    'x-kxco-pq-signature': ['pqOk'],
    'x-kxco-pq-kid':       ['kidOk', 'pqOk'],
  }
  for (const [name, failing] of Object.entries(fails)) {
    const value = signed[name]
    for (const bad of [[value], [value, value], { toString: () => value }, 5, null]) {
      const result = webhook.verifyDelivery({
        headers: { ...signed, [name]: bad },
        rawBody: 'x', hmacSecret: 's', pqPublicKey: publicKey, pinnedKid: kid,
      })
      for (const check of ['timestampOk', 'kidOk', 'hmacOk', 'pqOk']) {
        assert.equal(result[check], !failing.includes(check), `${name} as ${JSON.stringify(bad)}: ${check}`)
      }
    }
  }
})
