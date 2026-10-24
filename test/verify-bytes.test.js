// verify() takes the signature as hex or as raw bytes.
//
// sign() returns hex, and verify() has always taken hex. A signer that returns
// the raw bytes, such as a hardware security module or another library, hands
// over a Uint8Array or a Buffer. Until 1.12.0 verify() returned false for that
// whatever it held: hexToBytes refused anything that was not a string, and the
// refusal was read as a failed verification, so a valid signature looked like a
// bad one.
//
// These tests pin both halves of the change. Hex, a Uint8Array and a Buffer of
// the same signature give the same answer, for every signature module, on
// whichever backend is live. And everything that failed before still fails: a
// changed byte, a wrong length, a string that is not hex, and any value that is
// neither a string nor a Uint8Array.
//
// The independent signature comes from @noble/post-quantum called directly, as
// raw bytes with no hex anywhere on its path. On Node 24 and later this package
// verifies through OpenSSL wherever OpenSSL provides the set, so there that case
// is also a cross-implementation check.
// `KXCO_PQ_BACKEND=javascript npm test` runs the file on the JavaScript backend.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { slh_dsa_sha2_192s } from '@noble/post-quantum/slh-dsa.js'
import { native } from '#native'

import { mlDsa, mlDsa87, slhDsa, backend, isNative } from '../src/index.js'

const SIGNERS = [
  // name, module, the same primitive called directly, signature bytes
  ['ML-DSA-65', mlDsa, ml_dsa65, 3309],
  ['ML-DSA-87', mlDsa87, ml_dsa87, 4627],
  ['SLH-DSA-SHA2-192s', slhDsa, slh_dsa_sha2_192s, 16224],
]

const MASTER = new Uint8Array(32).fill(0x42)
const MESSAGE = new TextEncoder().encode('verify takes the signature as bytes')

// One key and two signatures per set, made once. SLH-DSA signing costs seconds
// on the JavaScript backend, so nothing below signs again without a reason.
const FIXTURES = SIGNERS.map(([name, impl, primitive, sigLen]) => {
  const { publicKey, secretKey } = impl.keypairFromMaster(MASTER)
  const hex = impl.sign(secretKey, MESSAGE)
  const independent = primitive.sign(MESSAGE, secretKey)
  return { name, impl, sigLen, publicKey, secretKey, hex, independent }
})

// A plain Uint8Array, not a Buffer, so the Uint8Array case is really tested.
const plainBytes = (hex) => new Uint8Array(Buffer.from(hex, 'hex'))

test('a hex signature from sign() verifies, unchanged', (t) => {
  // Records which backend each set ran on, so a pass says what it covered.
  t.diagnostic(`backend: ${backend().kind}`)
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    t.diagnostic(`${name}: ${isNative(name) ? 'openssl' : 'javascript'}`)
    assert.equal(typeof hex, 'string', `${name}: sign() must still return hex`)
    assert.equal(hex.length, sigLen * 2, `${name}: hex length`)
    assert.equal(impl.verify(publicKey, MESSAGE, hex), true, `${name}: lower-case hex`)
    assert.equal(impl.verify(publicKey, MESSAGE, hex.toUpperCase()), true, `${name}: upper-case hex`)
  }
})

test('the same signature verifies as a Uint8Array and as a Buffer', () => {
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    const u8 = plainBytes(hex)
    assert.equal(u8.constructor.name, 'Uint8Array', `${name}: the control must be a plain Uint8Array`)
    assert.equal(u8.length, sigLen)
    assert.equal(impl.verify(publicKey, MESSAGE, u8), true, `${name}: Uint8Array`)

    const buf = Buffer.from(hex, 'hex')
    assert.ok(Buffer.isBuffer(buf))
    assert.equal(impl.verify(publicKey, MESSAGE, buf), true, `${name}: Buffer`)
  }
})

test('a signature held in a view over a larger allocation verifies', () => {
  // A Buffer from a pool, or a slice of a received frame, starts part-way into
  // its ArrayBuffer. Each backend must read the view, not the whole buffer.
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    const sig = Buffer.from(hex, 'hex')
    const frame = Buffer.alloc(sigLen + 64, 0xee)
    sig.copy(frame, 17)

    const bufView = frame.subarray(17, 17 + sigLen)
    const u8View = new Uint8Array(frame.buffer, frame.byteOffset + 17, sigLen)
    assert.notEqual(u8View.byteOffset, 0)
    assert.equal(impl.verify(publicKey, MESSAGE, bufView), true, `${name}: Buffer view`)
    assert.equal(impl.verify(publicKey, MESSAGE, u8View), true, `${name}: Uint8Array view`)

    // and the same window one byte off is a different signature
    assert.equal(impl.verify(publicKey, MESSAGE, frame.subarray(16, 16 + sigLen)), false, `${name}: shifted view`)
  }
})

test('raw bytes from an independent signer verify, as bytes and as hex', () => {
  for (const { name, impl, sigLen, publicKey, independent } of FIXTURES) {
    assert.ok(independent instanceof Uint8Array, `${name}: the independent signer returns bytes`)
    assert.equal(independent.length, sigLen)
    assert.equal(impl.verify(publicKey, MESSAGE, independent), true, `${name}: Uint8Array`)
    assert.equal(impl.verify(publicKey, MESSAGE, Buffer.from(independent)), true, `${name}: Buffer`)
    assert.equal(impl.verify(publicKey, MESSAGE, Buffer.from(independent).toString('hex')), true, `${name}: hex`)
  }
})

test('bytes reach the OpenSSL backend intact', (t) => {
  // Called directly, so this proves the native path reads a Uint8Array, a
  // Buffer and a view correctly regardless of which backend verify() picks.
  if (native === null) {
    t.skip('no OpenSSL backend in this process')
    return
  }
  for (const { name, sigLen, publicKey, hex, independent } of FIXTURES) {
    if (!native.supports(name)) {
      t.diagnostic(`${name}: not provided by this OpenSSL, the JavaScript backend covers it`)
      continue
    }
    const frame = Buffer.alloc(sigLen + 8)
    Buffer.from(hex, 'hex').copy(frame, 5)
    assert.equal(native.verify(name, publicKey, MESSAGE, plainBytes(hex)), true, `${name}: Uint8Array`)
    assert.equal(native.verify(name, publicKey, MESSAGE, Buffer.from(hex, 'hex')), true, `${name}: Buffer`)
    assert.equal(native.verify(name, publicKey, MESSAGE, frame.subarray(5, 5 + sigLen)), true, `${name}: view`)
    assert.equal(native.verify(name, publicKey, MESSAGE, independent), true, `${name}: independent signer`)
  }
})

test('control: one byte changed in a byte signature returns false', () => {
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    for (const at of [0, sigLen >> 1, sigLen - 1]) {
      const u8 = plainBytes(hex)
      u8[at] ^= 0x01
      assert.equal(impl.verify(publicKey, MESSAGE, u8), false, `${name}: Uint8Array, byte ${at}`)
      assert.equal(impl.verify(publicKey, MESSAGE, Buffer.from(u8)), false, `${name}: Buffer, byte ${at}`)
    }
    // The unmodified signature still verifies, so the falses above are about
    // the changed byte and not about the harness.
    assert.equal(impl.verify(publicKey, MESSAGE, plainBytes(hex)), true, `${name}: control`)
  }
})

test('control: a byte signature of the wrong length returns false', () => {
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    const sig = plainBytes(hex)
    const long = new Uint8Array(sigLen + 1)
    long.set(sig)
    for (const [label, bad] of [
      ['empty', new Uint8Array(0)],
      ['one byte short', sig.subarray(0, sigLen - 1)],
      ['one byte long', long],
      ['twice the length', Buffer.concat([sig, sig])],
    ]) {
      assert.equal(impl.verify(publicKey, MESSAGE, bad), false, `${name}: ${label}`)
    }
  }
})

test('control: a byte signature from a different parameter set returns false', () => {
  const [mlDsa65, mlDsa87Fixture] = FIXTURES
  assert.equal(mlDsa87.verify(mlDsa87Fixture.publicKey, MESSAGE, plainBytes(mlDsa65.hex)), false)
  assert.equal(mlDsa.verify(mlDsa65.publicKey, MESSAGE, plainBytes(mlDsa87Fixture.hex)), false)
})

test('control: a string that is not hex returns false, as before', () => {
  for (const { name, impl, sigLen, publicKey, hex } of FIXTURES) {
    for (const [label, bad] of [
      ['empty', ''],
      ['odd length', hex.slice(1)],
      ['0x prefix', `0x${hex}`],
      ['one character not hex', `g${hex.slice(1)}`],
      ['trailing whitespace', `${hex} `],
      ['not hex at all', 'zz'.repeat(sigLen)],
      ['base64 of the signature', Buffer.from(hex, 'hex').toString('base64')],
    ]) {
      assert.equal(impl.verify(publicKey, MESSAGE, bad), false, `${name}: ${label}`)
    }
  }
})

test('anything that is neither a string nor a Uint8Array returns false and does not throw', () => {
  // Each one carries the genuine signature where it can carry anything, so the
  // false is the type being refused and not the content.
  for (const { name, impl, publicKey, hex } of FIXTURES) {
    const sig = plainBytes(hex)
    for (const [label, bad] of [
      ['undefined', undefined],
      ['null', null],
      ['a number', 1],
      ['a bigint', 1n],
      ['a boolean', true],
      ['an object', {}],
      ['an array of the bytes', Array.from(sig)],
      ['an ArrayBuffer of the bytes', sig.slice().buffer],
      ['a DataView of the bytes', new DataView(sig.slice().buffer)],
      ['an Int8Array of the bytes', new Int8Array(sig.slice().buffer)],
      ['a Uint8ClampedArray of the bytes', new Uint8ClampedArray(sig.slice().buffer)],
      ['a Uint16Array', new Uint16Array(sig.length)],
      ['an object with the hex inside', { hex }],
    ]) {
      assert.equal(impl.verify(publicKey, MESSAGE, bad), false, `${name}: ${label}`)
    }
  }
})

test('a byte signature honours the context, and misuse of opts still throws', () => {
  // ML-DSA only: SLH-DSA takes the same option through the same code, and
  // signing it again under a context would cost seconds for no new path.
  for (const { name, impl, publicKey, secretKey } of FIXTURES.slice(0, 2)) {
    const sig = plainBytes(impl.sign(secretKey, MESSAGE, { context: 'kxco-v1' }))
    assert.equal(impl.verify(publicKey, MESSAGE, sig, { context: 'kxco-v1' }), true, `${name}: same context`)
    assert.equal(impl.verify(publicKey, MESSAGE, sig), false, `${name}: no context`)
    assert.equal(impl.verify(publicKey, MESSAGE, sig, { context: 'other-v1' }), false, `${name}: other context`)

    assert.throws(() => impl.verify(publicKey, MESSAGE, sig, { context: new Uint8Array(256) }), RangeError)
    assert.throws(() => impl.verify(publicKey, MESSAGE, sig, 'kxco-v1'), TypeError)
  }
})
