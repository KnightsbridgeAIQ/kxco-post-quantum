// requireNativeBackend: the fail-closed assertion for deployments that must not
// silently fall back to the JavaScript implementation.
//
// This file is its own negative control, without any mocking. CI runs the suite
// on Node 20, 22 and 24. Node 20 and 22 have no OpenSSL 3.5 post-quantum
// primitives, so the JavaScript backend is live there and the refusal path is
// exercised for real; Node 24 exercises the accept path. Each test asserts the
// behaviour the live backend should produce, so both are covered by CI rather
// than by a stub that could drift from the real module.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { execFileSync } from 'node:child_process'
import { backend, isNative, requireNativeBackend, requireBackend } from '../src/index.js'

const NATIVE = backend().kind === 'openssl'

test('it agrees with backend() about which implementation is live', () => {
  if (NATIVE) {
    const b = requireNativeBackend()
    assert.equal(b.kind, 'openssl')
    assert.ok(b.openssl, 'the accepted backend should name its OpenSSL version')
  } else {
    assert.throws(
      () => requireNativeBackend(),
      (e) => {
        assert.equal(e.code, 'ERR_KXCO_PQ_BACKEND')
        assert.equal(e.actual, 'javascript')
        assert.match(e.message, /native backend is required/)
        return true
      },
      'it must refuse when the JavaScript backend is live',
    )
  }
})

test('a parameter set the backend cannot provide is refused by name', () => {
  if (!NATIVE) return   // covered by the test above on this runtime
  assert.throws(
    () => requireNativeBackend(['ML-DSA-65', 'NOT-A-REAL-SET']),
    (e) => {
      assert.equal(e.code, 'ERR_KXCO_PQ_BACKEND')
      assert.deepEqual(e.missing, ['NOT-A-REAL-SET'])
      assert.ok(Array.isArray(e.available), 'it should say what is available')
      return true
    },
  )
})

test('the sets it reports as native are the sets it accepts', () => {
  if (!NATIVE) return
  const sets = backend().parameterSets ?? []
  assert.ok(sets.length > 0, 'the native backend should list its parameter sets')
  for (const alg of sets) {
    assert.ok(isNative(alg), `${alg} is listed but isNative says otherwise`)
  }
  assert.doesNotThrow(() => requireNativeBackend(sets))
})

test('it asserts, it does not switch', () => {
  const before = backend()
  try { requireNativeBackend(['NOT-A-REAL-SET']) } catch {}
  assert.deepEqual(backend(), before, 'calling it must not change which backend is live')
})

// ---------------------------------------------------------------------------
// KXCO_PQ_BACKEND, the operator's pin.
//
// Both implementations are going to algorithm validation, so a deployment
// under a control that names a certificate has to be able to pin the one its
// certificate covers. For some of them that is the JavaScript implementation,
// which requireNativeBackend() cannot express because it only ever asserts
// OpenSSL.
//
// Each of these runs in its own process, because the pin is read at import and
// a test that mutated process.env afterwards would prove nothing.
// ---------------------------------------------------------------------------

function inProcess(env, code) {
  return execFileSync(process.execPath, ['--input-type=module', '-e', code], {
    env: { ...process.env, ...env },
  }).toString().trim()
}

test('KXCO_PQ_BACKEND=javascript pins the process off OpenSSL', () => {
  const out = JSON.parse(inProcess({ KXCO_PQ_BACKEND: 'javascript' }, `
    import { backend, isNative } from './src/index.js'
    process.stdout.write(JSON.stringify({ b: backend(), n: isNative('ML-DSA-65') }))
  `))
  assert.equal(out.b.kind, 'javascript')
  assert.equal(out.n, false)
  assert.equal(out.b.pinned, 'javascript')
})

test('a pinned process says it was pinned, not that the runtime cannot do it', () => {
  // These are two different facts and an evidence bundle that conflated them
  // would be wrong: absent means the runtime cannot, pinned means it can and
  // the operator said not to.
  const out = JSON.parse(inProcess({ KXCO_PQ_BACKEND: 'javascript' }, `
    import { backend } from './src/index.js'
    process.stdout.write(JSON.stringify(backend()))
  `))
  assert.match(out.reason, /KXCO_PQ_BACKEND=javascript pins/)
  assert.doesNotMatch(out.reason, /does not provide/)
})

test('a misspelled pin throws at import rather than doing nothing', () => {
  // A pin that silently did nothing would leave an operator believing a
  // control was in force when it was not.
  assert.throws(
    () => inProcess({ KXCO_PQ_BACKEND: 'openss1' }, `import './src/index.js'`),
    (err) => /must be 'openssl' or 'javascript'/.test(String(err.stderr ?? err)),
  )
})

test('a signature made under the pin still verifies on the other backend', () => {
  // The pin changes which implementation computes, never what it computes.
  const signed = inProcess({ KXCO_PQ_BACKEND: 'javascript' }, `
    import { mlDsa } from './src/index.js'
    const kp = mlDsa.keypairFromMaster('pin-wire-compat-master')
    process.stdout.write(JSON.stringify({
      pk: Buffer.from(kp.publicKey).toString('hex'),
      sig: mlDsa.sign(kp.secretKey, 'pinned message'),
    }))
  `)
  const { pk, sig } = JSON.parse(signed)
  const out = JSON.parse(inProcess({ KXCO_PQ_BACKEND: '' }, `
    import { mlDsa, backend } from './src/index.js'
    process.stdout.write(JSON.stringify({
      kind: backend().kind,
      ok: mlDsa.verify(Buffer.from(${JSON.stringify(pk)}, 'hex'), 'pinned message', ${JSON.stringify(sig)}),
    }))
  `))
  assert.equal(out.ok, true, 'the two implementations must stay interchangeable on the wire')
})

test('requireBackend asserts either implementation, and rejects a bad name', () => {
  assert.equal(requireBackend(backend().kind).kind, backend().kind)
  assert.throws(() => requireBackend('rust'), { code: 'ERR_KXCO_PQ_BACKEND' })
  if (NATIVE) {
    // Asserting javascript on an unpinned OpenSSL process must fail: the
    // function reports, the environment decides.
    assert.throws(() => requireBackend('javascript'), { code: 'ERR_KXCO_PQ_BACKEND' })
  }
})

test('requireNativeBackend still means what it meant', () => {
  if (NATIVE) assert.equal(requireNativeBackend().kind, 'openssl')
  else assert.throws(() => requireNativeBackend(), { code: 'ERR_KXCO_PQ_BACKEND' })
})
