// Tests for the self-contained module at kxco-post-quantum/fips.
//
// The module runs only from a manifest signed with the ML-DSA-87 release key,
// which a test cannot hold. So each test copies src/fips/ to a temporary
// directory, puts a throwaway test key in place of the release key, builds and
// signs the manifest with it, and imports the copy. Every failure path is
// produced the same way: by changing the copy, never by a hook in the module.
//
// The module draws entropy from /dev/urandom, so the tests that need a running
// module are skipped where that device does not exist (Windows). CI runs Linux.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SRC = join(ROOT, 'src', 'fips')
const MANIFEST_SCRIPT = join(ROOT, 'scripts', 'build-fips-manifest.mjs')
const LINUX = existsSync('/dev/urandom')
const needsEntropy = LINUX ? {} : { skip: 'needs /dev/urandom; the module claims Linux only' }

const hex = (u8) => Buffer.from(u8).toString('hex')
const TEST_KEY = ml_dsa87.keygen()
const OTHER_KEY = ml_dsa87.keygen()

function fixture({ beforeSign, afterSign, signWith = TEST_KEY } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-fips-'))
  cpSync(SRC, dir, { recursive: true })
  rmSync(join(dir, 'integrity.json'), { force: true })
  rmSync(join(dir, 'integrity.json.sig'), { force: true })
  writeFileSync(join(dir, 'release-key.js'), `export const RELEASE_KEY_ML_DSA_87 = '${hex(TEST_KEY.publicKey)}'\n`)
  beforeSign?.(dir)
  execFileSync(process.execPath, [MANIFEST_SCRIPT, dir], { stdio: 'ignore' })
  const manifest = readFileSync(join(dir, 'integrity.json'))
  writeFileSync(join(dir, 'integrity.json.sig'), hex(ml_dsa87.sign(manifest, signWith.secretKey)) + '\n')
  afterSign?.(dir)
  return dir
}
const load = (dir) => import(pathToFileURL(join(dir, 'index.js')).href)
const replaceIn = (dir, file, from, to) => {
  const p = join(dir, file)
  const body = readFileSync(p, 'utf8')
  assert.ok(body.includes(from), `fixture edit target not found in ${file}`)
  writeFileSync(p, body.replace(from, to))
}
const isFipsError = (err) => err.code === 'ERR_KXCO_PQ_FIPS'

test('an unsigned checkout of the repository stays in the error state', async () => {
  const fips = await import('../src/fips/index.js')
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /no signed integrity manifest/)
  assert.throws(() => fips.generateKeypair('ML-DSA-87'), isFipsError)
})

test('the embedded release key is release-signing-key-87.pub.hex', async () => {
  const { RELEASE_KEY_ML_DSA_87 } = await import('../src/fips/release-key.js')
  assert.equal(RELEASE_KEY_ML_DSA_87, readFileSync(join(ROOT, 'release-signing-key-87.pub.hex'), 'utf8').trim())
})

test('a signed module passes its self-tests and offers every service', needsEntropy, async () => {
  const fips = await load(fixture())
  const s = fips.status()
  assert.equal(s.state, 'operational', s.reason)
  assert.equal(s.module, 'kxco-post-quantum/fips')
  assert.equal(s.version, JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version)
  assert.match(s.caveat, /No assurance of the minimum strength/)

  for (const alg of ['ML-DSA-65', 'ML-DSA-87']) {
    const kp = fips.generateKeypair(alg)
    assert.equal(kp.seed.length, 32)
    const sig = fips.sign(alg, kp.secretKey, 'message', { context: 'ctx' })
    assert.equal(fips.verify(alg, kp.publicKey, 'message', sig, { context: 'ctx' }), true)
    assert.equal(fips.verify(alg, kp.publicKey, 'message', sig), false, 'a context-bound signature must not verify without it')
    assert.equal(fips.verify(alg, kp.publicKey, 'other', sig, { context: 'ctx' }), false)
    const again = fips.keypairFromSeed(alg, kp.seed)
    assert.deepEqual(again.publicKey, kp.publicKey)
  }
  for (const alg of ['ML-KEM-768', 'ML-KEM-1024']) {
    const kp = fips.generateKeypair(alg)
    assert.equal(kp.seed.length, 64)
    const { cipherText, sharedSecret } = fips.encapsulate(alg, kp.publicKey)
    assert.deepEqual(fips.decapsulate(alg, cipherText, kp.secretKey), sharedSecret)
    const tampered = cipherText.slice()
    tampered[0] ^= 1
    assert.notDeepEqual(fips.decapsulate(alg, tampered, kp.secretKey), sharedSecret, 'implicit rejection')
    assert.deepEqual(fips.keypairFromSeed(alg, kp.seed).secretKey, kp.secretKey)
  }
  assert.equal(fips.selfTest().state, 'operational')
  assert.equal(fips.status().state, 'operational')
})

test('caller mistakes are refused without entering the error state', needsEntropy, async () => {
  const fips = await load(fixture())
  assert.throws(() => fips.generateKeypair('ML-DSA-44'), RangeError)
  assert.throws(() => fips.keypairFromSeed('ML-KEM-1024', new Uint8Array(32)), RangeError)
  assert.throws(() => fips.sign('ML-DSA-87', new Uint8Array(10), 'm', { context: 'x'.repeat(256) }), RangeError)
  // FIPS 203 section 7.2: an encapsulation key with a coefficient out of range.
  const ek = fips.generateKeypair('ML-KEM-1024').publicKey.slice()
  ek[0] = 0xff
  ek[1] = 0xff
  assert.throws(() => fips.encapsulate('ML-KEM-1024', ek))
  assert.equal(fips.status().state, 'operational')
})

test('zeroize overwrites the buffers it is given', async () => {
  const fips = await import('../src/fips/index.js')
  const a = new Uint8Array([1, 2, 3])
  fips.zeroize(a)
  assert.deepEqual(a, new Uint8Array(3))
})

test('a file changed after signing stops the module', needsEntropy, async () => {
  const fips = await load(fixture({ afterSign: (d) => appendFileSync(join(d, 'vendor', 'hashes', 'sha3.js'), '\n') }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /vendor\/hashes\/sha3\.js does not match its digest/)
  assert.throws(() => fips.encapsulate('ML-KEM-1024', new Uint8Array(1568)), isFipsError)
})

test('a file not in the manifest stops the module', needsEntropy, async () => {
  const fips = await load(fixture({ afterSign: (d) => writeFileSync(join(d, 'extra.js'), 'export {}\n') }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /not in the manifest \(extra\.js\)/)
})

test('a manifest signed by any other key stops the module', needsEntropy, async () => {
  const fips = await load(fixture({ signWith: OTHER_KEY }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /does not verify under the ML-DSA-87 release key/)
})

test('a failing known-answer test puts the module in the error state', needsEntropy, async () => {
  const kat = (await import('../src/fips/kat.js')).KAT
  const wrong = (kat.mlKemEncaps.k[0] === '0' ? '1' : '0') + kat.mlKemEncaps.k.slice(1)
  const fips = await load(fixture({ beforeSign: (d) => replaceIn(d, 'kat.js', kat.mlKemEncaps.k, wrong) }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /self-test failed: ML-KEM-1024 encapsulation/)
  assert.throws(() => fips.generateKeypair('ML-DSA-87'), isFipsError)
})

test('a failing pairwise consistency test puts the module in the error state', needsEntropy, async () => {
  const fips = await load(fixture({
    beforeSign: (d) => replaceIn(d, 'module.js', 'ok = equal(sharedSecret, recovered)', 'ok = equal(sharedSecret, recovered) && false'),
  }))
  assert.equal(fips.status().state, 'operational')
  assert.throws(() => fips.generateKeypair('ML-KEM-1024'), isFipsError)
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /pairwise consistency test failed/)
  assert.throws(() => fips.generateKeypair('ML-DSA-87'), isFipsError, 'every service stays refused')
})

test('a failing self-test before the integrity test puts the module in the error state', needsEntropy, async () => {
  const kat = (await import('../src/fips/kat.js')).KAT
  const wrong = (kat.sha256.md[0] === '0' ? '1' : '0') + kat.sha256.md.slice(1)
  const fips = await load(fixture({ beforeSign: (d) => replaceIn(d, 'kat.js', kat.sha256.md, wrong) }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /self-test failed: SHA-256/)
})

test('a failing DRBG self-test puts the module in the error state', needsEntropy, async () => {
  const kat = (await import('../src/fips/kat.js')).KAT
  const h = kat.hmacDrbg.returnedSha256
  const wrong = (h[0] === '0' ? '1' : '0') + h.slice(1)
  const fips = await load(fixture({ beforeSign: (d) => replaceIn(d, 'kat.js', h, wrong) }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /self-test failed: HMAC_DRBG SHA-512/)
})

test('a failing ML-DSA pairwise test puts the module in the error state', needsEntropy, async () => {
  const fips = await load(fixture({
    beforeSign: (d) => replaceIn(d, 'module.js', 'ok = dsa.verify(sig, PCT_MESSAGE, publicKey) === true', 'ok = dsa.verify(sig, PCT_MESSAGE, publicKey) === true && false'),
  }))
  assert.throws(() => fips.generateKeypair('ML-DSA-87'), isFipsError)
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /pairwise consistency test failed for a generated ML-DSA key pair/)
})

test('a missing entropy source puts the module in the error state', needsEntropy, async () => {
  const fips = await load(fixture({ beforeSign: (d) => replaceIn(d, 'entropy.js', "'/dev/urandom'", "'/dev/kxco-no-such-device'") }))
  assert.equal(fips.status().state, 'error')
  assert.match(fips.status().reason, /DRBG instantiation failed/)
})

test('a corrupted decapsulation key and a short ciphertext are refused without entering the error state', needsEntropy, async () => {
  const fips = await load(fixture())
  const kp = fips.generateKeypair('ML-KEM-1024')
  const { cipherText } = fips.encapsulate('ML-KEM-1024', kp.publicKey)
  // FIPS 203 section 7.3 hash check. dk is dk_PKE (384k bytes) || ek (384k + 32)
  // || H(ek) (32) || z (32), so with k = 4 H(ek) starts at byte 768k + 32 = 3104.
  const dk = kp.secretKey.slice()
  dk[3104] ^= 1
  assert.throws(() => fips.decapsulate('ML-KEM-1024', cipherText, dk))
  assert.throws(() => fips.decapsulate('ML-KEM-1024', cipherText.subarray(0, 100), kp.secretKey))
  assert.equal(fips.status().state, 'operational')
})

test('nothing in the module calls crypto.getRandomValues', needsEntropy, () => {
  const dir = fixture()
  const script = `
    globalThis.crypto.getRandomValues = () => { throw new Error('getRandomValues was called') }
    const fips = await import(${JSON.stringify(pathToFileURL(join(dir, 'index.js')).href)})
    if (fips.status().state !== 'operational') throw new Error(fips.status().reason)
    for (const alg of ['ML-DSA-65', 'ML-DSA-87']) {
      const kp = fips.generateKeypair(alg)
      if (!fips.verify(alg, kp.publicKey, 'm', fips.sign(alg, kp.secretKey, 'm'))) throw new Error('verify')
    }
    for (const alg of ['ML-KEM-768', 'ML-KEM-1024']) {
      const kp = fips.generateKeypair(alg)
      fips.decapsulate(alg, fips.encapsulate(alg, kp.publicKey).cipherText, kp.secretKey)
    }
    fips.selfTest()
    // The control: the same vendored noble code, called the way the module never
    // calls it (no seed of its own), does reach getRandomValues and fails. So the
    // passes above mean the module supplied every random value, not that the
    // patch was never consulted.
    const { ml_dsa87 } = await import(${JSON.stringify(pathToFileURL(join(dir, 'vendor', 'post-quantum', 'ml-dsa.js')).href)})
    let fired = false
    try { ml_dsa87.keygen() } catch (err) { fired = /getRandomValues was called/.test(err.message) }
    if (!fired) throw new Error('control: noble did not reach the patched getRandomValues')
    console.log('ok')
  `
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' })
  assert.equal(out.trim(), 'ok')
})
