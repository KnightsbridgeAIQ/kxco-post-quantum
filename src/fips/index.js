// kxco-post-quantum/fips: a self-contained cryptographic module designed against
// the FIPS 140-3 Level 1 software requirements. It is not a validated module: no
// laboratory has tested it and NIST has issued no certificate for it.
//
// What happens on import, in this order:
//   1. The module refuses to run from anything but a local file.
//   2. The self-tests for SHA-256 and ML-DSA-87 verification run, because the
//      integrity test uses both (FIPS 140-3 IG 10.2.A).
//   3. The integrity test: integrity.json, signed with the ML-DSA-87 release
//      key, must verify, and every file in this directory must match its
//      SHA-256 digest there, with no file missing and none extra.
//   4. Only then are the services loaded, the remaining self-tests run and the
//      DRBG instantiated from the operating system's entropy source.
//
// Any failure puts the module into its error state. Import still succeeds, so a
// caller can read status(), but every cryptographic service throws an error
// with code ERR_KXCO_PQ_FIPS until the process restarts.
//
// The module offers only approved services, so a call that returns has run as
// an approved service (FIPS 140-3 IG 2.4.C, implicit indication).

import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256 } from './vendor/hashes/sha2.js'
import { ml_dsa87 } from './vendor/post-quantum/ml-dsa.js'
import { runIntegrityCasts } from './selftest.js'
import { RELEASE_KEY_ML_DSA_87 } from './release-key.js'

export const MODULE_NAME = 'kxco-post-quantum/fips'
export const CAVEAT = 'No assurance of the minimum strength of generated SSPs (e.g., keys).'
export const ALGORITHMS = Object.freeze(['ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87'])

const HERE = dirname(fileURLToPath(import.meta.url))
const MANIFEST = 'integrity.json'
const SIGNATURE = 'integrity.json.sig'

let state = 'self-test'
let reason = null
let version = null
let services = null

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function toHex(u8) {
  let s = ''
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0')
  return s
}

function filesIn(dir) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...filesIn(p))
    else out.push(relative(HERE, p).split(sep).join('/'))
  }
  return out
}

function integrityTest() {
  let manifestBytes, signature
  try {
    manifestBytes = readFileSync(join(HERE, MANIFEST))
    signature = readFileSync(join(HERE, SIGNATURE), 'utf8').trim()
  } catch {
    throw new Error('integrity test failed: no signed integrity manifest; the module runs only from a signed release')
  }
  if (!ml_dsa87.verify(hexToBytes(signature), manifestBytes, hexToBytes(RELEASE_KEY_ML_DSA_87))) {
    throw new Error('integrity test failed: the manifest signature does not verify under the ML-DSA-87 release key')
  }
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes))
  const listed = Object.keys(manifest.files ?? {})
  const present = filesIn(HERE).filter((f) => f !== MANIFEST && f !== SIGNATURE)
  const missing = listed.filter((f) => !present.includes(f))
  const extra = present.filter((f) => !Object.hasOwn(manifest.files, f))
  if (missing.length || extra.length) {
    throw new Error(`integrity test failed: ${missing.length} file(s) missing, ${extra.length} not in the manifest` +
      `${extra.length ? ` (${extra.join(', ')})` : ''}`)
  }
  for (const f of listed) {
    if (toHex(sha256(readFileSync(join(HERE, ...f.split('/'))))) !== manifest.files[f]) {
      throw new Error(`integrity test failed: ${f} does not match its digest`)
    }
  }
  return manifest
}

function enterError(err) {
  state = 'error'
  reason = err?.message ?? String(err)
  if (services) {
    try { services.destroy() } catch {}
    services = null
  }
}

function fipsError(message) {
  const err = new Error(message)
  err.code = 'ERR_KXCO_PQ_FIPS'
  return err
}

function call(name, args) {
  if (state !== 'operational') {
    throw fipsError(`${MODULE_NAME} is in the ${state} state and offers no cryptographic service: ${reason}`)
  }
  try {
    return services[name](...args)
  } catch (err) {
    if (err?.fatal) {
      enterError(err)
      throw fipsError(`${MODULE_NAME} entered the error state: ${reason}`)
    }
    throw err
  }
}

try {
  if (new URL(import.meta.url).protocol !== 'file:') {
    throw new Error('the module must be loaded from a local file')
  }
  runIntegrityCasts()
  version = integrityTest().version ?? null
  const { start } = await import('./module.js')
  services = start()
  state = 'operational'
} catch (err) {
  enterError(err)
}

/** The module's name, version, state, the reason for an error state, and its entropy caveat. */
export function status() {
  return {
    module: MODULE_NAME,
    version,
    state,
    ...(reason ? { reason } : {}),
    caveat: CAVEAT,
    algorithms: ALGORITHMS,
  }
}

/** On-demand self-tests: the integrity test and every algorithm self-test, run again. */
export function selfTest() {
  if (state !== 'operational') throw fipsError(`${MODULE_NAME} is in the ${state} state: ${reason}`)
  try {
    runIntegrityCasts()
    integrityTest()
    services.runCasts()
  } catch (err) {
    enterError(err)
    throw fipsError(`${MODULE_NAME} entered the error state: ${reason}`)
  }
  return status()
}

export function generateKeypair(alg) { return call('generateKeypair', [alg]) }
export function keypairFromSeed(alg, seed) { return call('keypairFromSeed', [alg, seed]) }
export function encapsulate(alg, publicKey) { return call('encapsulate', [alg, publicKey]) }
export function decapsulate(alg, cipherText, secretKey) { return call('decapsulate', [alg, cipherText, secretKey]) }
export function sign(alg, secretKey, message, opts) { return call('sign', [alg, secretKey, message, opts]) }
export function verify(alg, publicKey, message, signature, opts) { return call('verify', [alg, publicKey, message, signature, opts]) }

/** Overwrite key material the caller holds. Available in every state. */
export function zeroize(...arrays) {
  for (const a of arrays) if (a instanceof Uint8Array) a.fill(0)
}
