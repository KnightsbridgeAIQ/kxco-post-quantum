// The FIPS module's cryptographic algorithm self-tests (CASTs).
//
// Each test runs an algorithm on fixed inputs and compares the result with a
// known answer from NIST's ACVP vectors (kat.js). A mismatch throws a fatal
// error, which puts the module into its error state. The tests follow FIPS 140-3
// IG 10.3.A: one test per algorithm covers every parameter set of it, so ML-KEM
// is tested at ML-KEM-1024 and ML-DSA at ML-DSA-87, the sets the module offers by
// default.
//
// SHA-256 and ML-DSA verification run first, on their own, because the
// integrity test uses them (IG 10.2.A). Everything else runs once the module's
// files have been verified.

import { sha256, sha512 } from './vendor/hashes/sha2.js'
import { hmac } from './vendor/hashes/hmac.js'
import { ml_kem1024 } from './vendor/post-quantum/ml-kem.js'
import { ml_dsa87 } from './vendor/post-quantum/ml-dsa.js'
import { KAT } from './kat.js'

export class FipsFatalError extends Error {
  constructor(message) {
    super(message)
    this.fatal = true
  }
}

function bytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function toHex(u8) {
  let s = ''
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0')
  return s
}
const digest = (u8) => toHex(sha256(u8))

function check(name, ok) {
  if (!ok) throw new FipsFatalError(`self-test failed: ${name}`)
}

export function castSha256() {
  check('SHA-256', toHex(sha256(bytes(KAT.sha256.msg))) === KAT.sha256.md)
}

export function castMlDsaVerify() {
  const t = KAT.mlDsaVerify
  const ok = ml_dsa87.verify(bytes(t.signature), bytes(t.message), bytes(t.pk), { context: bytes(t.context) })
  check('ML-DSA-87 signature verification', ok === true)
}

export function castSha512() {
  check('SHA-512', toHex(sha512(bytes(KAT.sha512.msg))) === KAT.sha512.md)
}

export function castHmac() {
  const t = KAT.hmacSha512
  const mac = toHex(hmac(sha512, bytes(t.key), bytes(t.msg)))
  check('HMAC-SHA2-512', mac.slice(0, t.mac.length) === t.mac)
}

// SP 800-90A section 11.3: instantiate, reseed and generate, in the order the
// NIST vector drives them.
export function castDrbg(HmacDrbg) {
  const t = KAT.hmacDrbg
  const drbg = new HmacDrbg()
  drbg.instantiate(bytes(t.entropyInput), bytes(t.nonce), bytes(t.personalization))
  let out
  for (const step of t.steps) {
    if (step.use === 'reSeed') drbg.reseed(bytes(step.entropyInput), bytes(step.additionalInput))
    else out = drbg.generate(t.returnedBytes, bytes(step.additionalInput))
  }
  drbg.uninstantiate()
  check('HMAC_DRBG SHA-512', out !== undefined && digest(out) === t.returnedSha256)
}

export function castMlKem() {
  const g = KAT.mlKemKeygen
  const seed = new Uint8Array([...bytes(g.d), ...bytes(g.z)])
  const k = ml_kem1024.keygen(seed)
  check('ML-KEM-1024 key generation', digest(k.publicKey) === g.ekSha256 && digest(k.secretKey) === g.dkSha256)

  const e = KAT.mlKemEncaps
  const r = ml_kem1024.encapsulate(bytes(e.ek), bytes(e.m))
  check('ML-KEM-1024 encapsulation', digest(r.cipherText) === e.cSha256 && toHex(r.sharedSecret) === e.k)

  const d = KAT.mlKemDecaps
  check('ML-KEM-1024 decapsulation', toHex(ml_kem1024.decapsulate(bytes(d.c), bytes(d.dk))) === d.k)

  // FIPS 203 implicit rejection: a ciphertext that does not decapsulate
  // correctly must yield J(z || c), not an error (IG 10.3.A Note 21).
  const j = KAT.mlKemReject
  check('ML-KEM-1024 implicit rejection', toHex(ml_kem1024.decapsulate(bytes(j.c), bytes(j.dk))) === j.k)
}

export function castMlDsa() {
  const g = KAT.mlDsaKeygen
  const k = ml_dsa87.keygen(bytes(g.seed))
  check('ML-DSA-87 key generation', digest(k.publicKey) === g.pkSha256 && digest(k.secretKey) === g.skSha256)

  const s = KAT.mlDsaSign
  const sig = ml_dsa87.sign(bytes(s.message), bytes(s.sk), { context: bytes(s.context), extraEntropy: bytes(s.rnd) })
  check('ML-DSA-87 signature generation', digest(sig) === s.signatureSha256)
}

// Before the integrity test (IG 10.2.A).
export function runIntegrityCasts() {
  castSha256()
  castMlDsaVerify()
}

// After the integrity test, and again on demand.
export function runAlgorithmCasts(HmacDrbg) {
  castSha512()
  castHmac()
  castDrbg(HmacDrbg)
  castMlKem()
  castMlDsa()
}
