// Property-based tests with fast-check.
//
// fuzz/fuzz.mjs throws arbitrary bytes at the parsers and asks one thing: fail
// closed. These ask the other half: for ANY valid input, does the primitive do
// exactly what it says? fast-check generates the inputs and, when a property
// breaks, shrinks the failing case to the smallest one that still breaks it,
// so a failure arrives as a minimal reproduction rather than a random blob.
//
// Runs on whichever backend is live. `KXCO_PQ_BACKEND=javascript npm test`
// runs it on the JavaScript implementation as well.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mlDsa, mlKem, fingerprint, kidEquals, deriveSeed, seed as seedmod, jws, webhook } from '../src/index.js'

// Signing is milliseconds per case, so a modest run count keeps the suite fast
// while still covering a spread of lengths, encodings and contexts.
const RUNS = { numRuns: 40 }

// `size: 'max'` spreads lengths over the whole range up to maxLength. Without
// it fast-check keeps them near ten, whatever maxLength says.
const master = fc.uint8Array({ minLength: 16, maxLength: 64 })
const info = fc.string({ minLength: 1, maxLength: 40 })
const message = fc.oneof(fc.uint8Array({ maxLength: 512, size: 'max' }), fc.string({ maxLength: 256, size: 'max' }))
// At most 255 bytes of UTF-8: 60 characters of up to 4 bytes each stays inside.
const context = fc.string({ maxLength: 60, size: 'max' })

// One key per run is enough: the properties are about messages and contexts.
const signer = mlDsa.keypairFromMaster(new Uint8Array(32).fill(7), 'property-tests-v1')

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('ML-DSA-65: any message signed under any context verifies under that context', () => {
  fc.assert(fc.property(message, context, (msg, ctx) => {
    const sig = mlDsa.sign(signer.secretKey, msg, { context: ctx })
    return mlDsa.verify(signer.publicKey, msg, sig, { context: ctx }) === true
  }), RUNS)
})

test('ML-DSA-65: a signature does not verify for a different message', () => {
  fc.assert(fc.property(fc.uint8Array({ minLength: 1, maxLength: 256, size: 'max' }), fc.nat(), (msg, at) => {
    const sig = mlDsa.sign(signer.secretKey, msg)
    const other = Uint8Array.from(msg)
    other[at % other.length] ^= 0x01
    return mlDsa.verify(signer.publicKey, other, sig) === false
  }), RUNS)
})

test('ML-DSA-65: a signature does not verify under a different context', () => {
  fc.assert(fc.property(message, context, context, (msg, a, b) => {
    fc.pre(a !== b)
    const sig = mlDsa.sign(signer.secretKey, msg, { context: a })
    return mlDsa.verify(signer.publicKey, msg, sig, { context: b }) === false
  }), RUNS)
})

test('ML-DSA-65: verify fails closed on an arbitrary signature', () => {
  // Junk of any length up to 4000 bytes, and junk of exactly the 3309 bytes an
  // ML-DSA-65 signature is, which is the only length that reaches the
  // verification arithmetic rather than stopping at the length check.
  const junk = fc.oneof(
    fc.uint8Array({ maxLength: 4000, size: 'max' }),
    fc.uint8Array({ minLength: 3309, maxLength: 3309 }),
  )
  fc.assert(fc.property(message, junk, (msg, sig) => {
    return mlDsa.verify(signer.publicKey, msg, Buffer.from(sig).toString('hex')) === false
  }), RUNS)
})

test('key derivation: the same master and info always give the same keys', () => {
  fc.assert(fc.property(master, info, (m, i) => {
    const a = mlDsa.keypairFromMaster(m, i)
    const b = mlDsa.keypairFromMaster(Uint8Array.from(m), i)
    return Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey)) && kidEquals(fingerprint(a.publicKey), fingerprint(b.publicKey))
  }), RUNS)
})

test('deriveSeed: returns exactly the length asked for, and different info gives different output', () => {
  fc.assert(fc.property(master, info, info, fc.integer({ min: 16, max: 128 }), (m, a, b, len) => {
    fc.pre(a !== b)
    const x = deriveSeed(m, a, len)
    const y = deriveSeed(m, b, len)
    return x.length === len && y.length === len && !Buffer.from(x).equals(Buffer.from(y))
  }), RUNS)
})

test('ML-KEM-768: decapsulation recovers exactly the encapsulated secret', () => {
  fc.assert(fc.property(master, info, (m, i) => {
    const k = mlKem.keypairFromMaster(m, i)
    const { ciphertext, sharedSecret } = mlKem.encapsulate(k.publicKey)
    const recovered = mlKem.decapsulate(ciphertext, k.secretKey)
    return sharedSecret.length === 32 && Buffer.from(recovered).equals(Buffer.from(sharedSecret))
  }), RUNS)
})

test('fingerprint: always 16 hex characters, and kidEquals agrees with equality', () => {
  fc.assert(fc.property(fc.uint8Array({ minLength: 1, maxLength: 2600, size: 'max' }), fc.uint8Array({ minLength: 1, maxLength: 2600, size: 'max' }), (a, b) => {
    const fa = fingerprint(a)
    const fb = fingerprint(b)
    return /^[0-9a-f]{16}$/.test(fa) && kidEquals(fa, fa) && kidEquals(fa, fb) === (fa === fb)
  }), RUNS)
})

test('compact JWS: any JSON payload round-trips, and a changed payload is refused', () => {
  // Keys carry a prefix so a generated key can never be `forged` (which would make
  // the tampered token identical to the real one) or `__proto__`.
  const key = fc.stringMatching(/^k_[a-z0-9]{1,10}$/)
  const payload = fc.dictionary(key, fc.oneof(fc.string({ maxLength: 40 }), fc.integer(), fc.boolean()), { maxKeys: 6 })
  fc.assert(fc.property(payload, (body) => {
    const token = jws.signJws(body, signer.secretKey)
    const ok = jws.verifyJws(token, signer.publicKey)
    const [h, , s] = token.split('.')
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...body, forged: true })).toString('base64url')}.${s}`
    return ok.valid === true && jws.verifyJws(forged, signer.publicKey).valid === false
  }), RUNS)
})

test('compact JWS: the header reader never throws on arbitrary text', () => {
  fc.assert(fc.property(fc.string({ maxLength: 300, size: 'max' }), (text) => {
    const h = jws.decodeJwsHeader(text)
    return h === null || (typeof h === 'object' && !Array.isArray(h))
  }), { numRuns: 500 })
})

test('seed-form JWK: export then import gives back the same key', () => {
  fc.assert(fc.property(master, info, (m, i) => {
    const key = mlDsa.keypairFromMaster(m, i)
    const back = seedmod.importJwk(seedmod.exportJwk('ML-DSA-65', key))
    return back.alg === 'ML-DSA-65' &&
      Buffer.from(back.publicKey).equals(Buffer.from(key.publicKey)) &&
      Buffer.from(back.seed).equals(Buffer.from(key.seed))
  }), RUNS)
})

test('webhook: a timestamp header that is not all digits never verifies, however it was signed', () => {
  const kid = fingerprint(signer.publicKey)
  const now = () => String(Math.floor(Date.now() / 1000))
  const text = fc.string({ maxLength: 20, size: 'max' })
  const malformed = fc.oneof(
    // The start of a body moved into the header, up to a '.'.
    text.map((x) => `${now()}.${x}`),
    // Anything before or after the digits.
    fc.tuple(fc.oneof(fc.constantFrom('', ' ', '+', '-'), text), text).map(([pre, post]) => `${pre}${now()}${post}`),
  ).filter((ts) => !/^[0-9]+$/.test(ts))
  fc.assert(fc.property(malformed, message, (ts, body) => {
    const r = webhook.verifyDelivery({
      headers: {
        'x-kxco-timestamp': ts,
        'x-kxco-signature': 'sha256=' + webhook.hmacHex('s', ts, body),
        'x-kxco-pq-signature': webhook.pqSign(signer.secretKey, ts, body),
        'x-kxco-pq-kid': kid,
      },
      rawBody: body, hmacSecret: 's', pqPublicKey: signer.publicKey, pinnedKid: kid,
    })
    return !r.timestampOk && !r.hmacOk && !r.pqOk
  }), RUNS)
})
