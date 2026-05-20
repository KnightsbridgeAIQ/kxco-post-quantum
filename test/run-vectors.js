// Run-vectors — verifies every entry in test/vectors.json against the library.
//
// Anyone can `git clone && npm install && node test/run-vectors.js` and see
// the same bit-for-bit outputs. This is the reproducibility claim.
//
// Exit code 0 = all pass. Exit code 1 = at least one mismatch.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import {
  mlDsa, mlKem, deriveSeed, fingerprint, webhook,
} from '../src/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'))

const sha256hex = (b) => createHash('sha256').update(b).digest('hex')

let pass = 0
let fail = 0
const failures = []

function check(group, name, expected, actual) {
  const ok = expected === actual ||
    (typeof expected === 'boolean' && expected === actual) ||
    (typeof expected === 'number'  && expected === actual)
  if (ok) {
    pass++
  } else {
    fail++
    failures.push({ group, name, expected, actual })
  }
}

// deriveSeed
for (const v of vectors.deriveSeed) {
  const master = Buffer.from(v.master_hex, 'hex')
  const got = deriveSeed(master, v.info, v.length).toString('hex')
  check('deriveSeed', v.name, v.expect_hex, got)
}

// mlDsa keypairFromMaster — pin SHA-256 of pub + secret bytes
for (const v of vectors.mlDsa_keypairFromMaster) {
  const master = Buffer.from(v.master_hex, 'hex')
  const kp = mlDsa.keypairFromMaster(master, v.info)
  check('mlDsa.keypairFromMaster', v.name + ' [publicKey_sha256]', v.publicKey_sha256, sha256hex(kp.publicKey))
  check('mlDsa.keypairFromMaster', v.name + ' [secretKey_sha256]', v.secretKey_sha256, sha256hex(kp.secretKey))
  check('mlDsa.keypairFromMaster', v.name + ' [publicKey_bytes]',  v.publicKey_bytes,  kp.publicKey.length)
  check('mlDsa.keypairFromMaster', v.name + ' [secretKey_bytes]',  v.secretKey_bytes,  kp.secretKey.length)
}

// mlDsa sign round-trip
for (const v of vectors.mlDsa_sign_roundtrip) {
  const master = Buffer.from(v.master_hex, 'hex')
  const kp = mlDsa.keypairFromMaster(master, v.info)
  const sig = mlDsa.sign(kp.secretKey, v.message_utf8)
  const verified = mlDsa.verify(kp.publicKey, v.message_utf8, sig)
  check('mlDsa.sign_roundtrip', v.name + ' [verify]', v.expect_verify, verified)
  check('mlDsa.sign_roundtrip', v.name + ' [sig_hex_length]', v.expect_sig_hex_length, sig.length)
}

// mlKem keypairFromMaster
for (const v of vectors.mlKem_keypairFromMaster) {
  const master = Buffer.from(v.master_hex, 'hex')
  const kp = mlKem.keypairFromMaster(master, v.info)
  check('mlKem.keypairFromMaster', v.name + ' [publicKey_sha256]', v.publicKey_sha256, sha256hex(kp.publicKey))
  check('mlKem.keypairFromMaster', v.name + ' [secretKey_sha256]', v.secretKey_sha256, sha256hex(kp.secretKey))
  check('mlKem.keypairFromMaster', v.name + ' [publicKey_bytes]',  v.publicKey_bytes,  kp.publicKey.length)
  check('mlKem.keypairFromMaster', v.name + ' [secretKey_bytes]',  v.secretKey_bytes,  kp.secretKey.length)
}

// mlKem encapsulate round-trip
for (const v of vectors.mlKem_encapsulate_roundtrip) {
  const master = Buffer.from(v.master_hex, 'hex')
  const kp = mlKem.keypairFromMaster(master, v.info)
  const { ciphertext, sharedSecret } = mlKem.encapsulate(kp.publicKey)
  const recovered = mlKem.decapsulate(ciphertext, kp.secretKey)
  check('mlKem.encapsulate_roundtrip', v.name + ' [secret_bytes]', v.expect_sharedSecret_bytes, sharedSecret.length)
  check('mlKem.encapsulate_roundtrip', v.name + ' [ct_bytes]',     v.expect_ciphertext_bytes,   ciphertext.length)
  check('mlKem.encapsulate_roundtrip', v.name + ' [recovered_eq]', sha256hex(sharedSecret),     sha256hex(recovered))
}

// fingerprint
for (const v of vectors.fingerprint) {
  let input
  if (v.input_hex)       input = Buffer.from(v.input_hex, 'hex')
  else if (v.input_utf8) input = Buffer.from(v.input_utf8, 'utf8')
  else if (v.input_source && v.input_source.includes('mlDsa.keypairFromMaster')) {
    input = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'platform-v1').publicKey
  }
  const got = fingerprint(input)
  check('fingerprint', v.name, v.expect_kid, got)
}

// webhook envelope
for (const v of vectors.webhook_envelope) {
  const got = webhook.envelope(v.timestamp, v.body_utf8).toString('hex')
  check('webhook.envelope', v.name, v.expect_envelope_hex, got)
}

// webhook hmac
for (const v of vectors.webhook_hmac) {
  const got = webhook.hmacHex(v.secret_utf8, v.timestamp, v.body_utf8)
  check('webhook.hmac', v.name, v.expect_hmac_hex, got)
}

// webhook hybrid round-trip with FRESH timestamp (vector's timestamp is stale on purpose; we use Date.now() here)
for (const v of vectors.webhook_hybrid_roundtrip) {
  const master = Buffer.from(v.master_hex, 'hex')
  const kp = mlDsa.keypairFromMaster(master, v.info)
  const kid = fingerprint(kp.publicKey)
  const freshTs = Math.floor(Date.now() / 1000).toString()
  const headers = webhook.signDelivery({
    rawBody:     v.body_utf8,
    hmacSecret:  v.hmac_secret_utf8,
    pqSecretKey: kp.secretKey,
    pqKid:       kid,
  })
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  const r = webhook.verifyDelivery({
    headers:     lower,
    rawBody:     v.body_utf8,
    hmacSecret:  v.hmac_secret_utf8,
    pqPublicKey: kp.publicKey,
    pinnedKid:   kid,
  })
  check('webhook.hybrid_roundtrip', v.name + ' [hmac_ok]', v.expect_hmac_ok, r.hmacOk)
  check('webhook.hybrid_roundtrip', v.name + ' [pq_ok]',   v.expect_pq_ok,   r.pqOk)
  check('webhook.hybrid_roundtrip', v.name + ' [ts_ok]',   v.expect_timestamp_ok_when_fresh, r.timestampOk)
}

// Report
console.log('')
console.log(`kxco-post-quantum test vectors`)
console.log(`Generated:  ${vectors.generated_at}`)
console.log(`Library:    ${vectors.library}`)
console.log(`Underlying: ${vectors.underlying_primitive}`)
console.log('')

if (fail === 0) {
  console.log(`✓ All ${pass} checks pass — library output matches pinned vectors bit-for-bit.`)
  process.exit(0)
} else {
  console.log(`✗ ${fail} failed, ${pass} passed.`)
  for (const f of failures) {
    console.log(`\n  GROUP:    ${f.group}`)
    console.log(`  NAME:     ${f.name}`)
    console.log(`  EXPECTED: ${f.expected}`)
    console.log(`  ACTUAL:   ${f.actual}`)
  }
  process.exit(1)
}
