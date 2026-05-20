// Generate canonical test vectors from the library and emit a vectors.json
// the runner can verify against. Run once when the library's output behaviour
// changes; otherwise vectors.json is the immutable record.
//
// Usage: node test/generate-vectors.js > test/vectors.json

import { createHash, createHmac } from 'node:crypto'
import {
  mlDsa, mlKem, deriveSeed, fingerprint, webhook,
} from '../src/index.js'

const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex')
const zero32  = Buffer.from('00'.repeat(32), 'hex')
const ones32  = Buffer.from('11'.repeat(32), 'hex')
const ffs32   = Buffer.from('ff'.repeat(32), 'hex')

function derive(master, info, length) {
  return deriveSeed(master, info, length).toString('hex')
}

function kpHashes(kp) {
  return {
    publicKey_sha256: sha256hex(kp.publicKey),
    publicKey_bytes:  kp.publicKey.length,
    secretKey_sha256: sha256hex(kp.secretKey),
    secretKey_bytes:  kp.secretKey.length,
  }
}

const ts = '1748000000'
const body = '{"event":"payment.settled","amount":1000}'
const hmacSecret = 'shared-secret-bytes'

const vectors = {
  version: '1.0',
  generated_at: new Date().toISOString(),
  description: 'Deterministic test vectors for kxco-post-quantum. Run test/run-vectors.js to verify these match the library output bit-for-bit.',
  library: 'kxco-post-quantum',
  underlying_primitive: '@noble/post-quantum',
  notes: [
    'ML-DSA-65 signatures are randomized — we cannot pin signature bytes. We pin keypair hashes and verify round-trip.',
    'ML-KEM encapsulation is randomized — we pin keypair hashes and verify decapsulate round-trip in the runner.',
    'All hex is lowercase. All UTF-8 strings are explicit.',
  ],

  deriveSeed: [
    {
      name: 'zero master, info=role-a, length=32',
      master_hex: zero32.toString('hex'),
      info: 'role-a',
      length: 32,
      expect_hex: derive(zero32, 'role-a', 32),
    },
    {
      name: 'zero master, info=role-b, length=32 (different info → different seed)',
      master_hex: zero32.toString('hex'),
      info: 'role-b',
      length: 32,
      expect_hex: derive(zero32, 'role-b', 32),
    },
    {
      name: '0x11 master, info=platform-v1, length=64',
      master_hex: ones32.toString('hex'),
      info: 'platform-v1',
      length: 64,
      expect_hex: derive(ones32, 'platform-v1', 64),
    },
  ],

  mlDsa_keypairFromMaster: [
    {
      name: 'zero master, info=platform-v1',
      master_hex: zero32.toString('hex'),
      info: 'platform-v1',
      ...kpHashes(mlDsa.keypairFromMaster(zero32, 'platform-v1')),
    },
    {
      name: '0xff master, info=test',
      master_hex: ffs32.toString('hex'),
      info: 'test',
      ...kpHashes(mlDsa.keypairFromMaster(ffs32, 'test')),
    },
  ],

  mlDsa_sign_roundtrip: [
    {
      name: 'sign known message with keypair from zero master; verify true',
      master_hex: zero32.toString('hex'),
      info: 'platform-v1',
      message_utf8: 'hello kxco',
      expect_verify: true,
      expect_sig_hex_length: 6618,
    },
  ],

  mlKem_keypairFromMaster: [
    {
      name: 'zero master, info=platform-v1',
      master_hex: zero32.toString('hex'),
      info: 'platform-v1',
      ...kpHashes(mlKem.keypairFromMaster(zero32, 'platform-v1')),
    },
  ],

  mlKem_encapsulate_roundtrip: [
    {
      name: 'encapsulate to keypair from zero master; decapsulate recovers same secret',
      master_hex: zero32.toString('hex'),
      info: 'platform-v1',
      expect_sharedSecret_bytes: 32,
      expect_ciphertext_bytes: 1088,
    },
  ],

  fingerprint: [
    {
      name: 'fingerprint of 32 zero bytes',
      input_hex: zero32.toString('hex'),
      expect_kid: fingerprint(zero32),
    },
    {
      name: 'fingerprint of 32 0xff bytes',
      input_hex: ffs32.toString('hex'),
      expect_kid: fingerprint(ffs32),
    },
    {
      name: "fingerprint of UTF-8 string 'kxco'",
      input_utf8: 'kxco',
      expect_kid: fingerprint(Buffer.from('kxco', 'utf8')),
    },
    {
      name: 'fingerprint of ML-DSA-65 platform pubkey from zero master',
      input_source: 'mlDsa.keypairFromMaster(0x00*32, "platform-v1").publicKey',
      expect_kid: fingerprint(mlDsa.keypairFromMaster(zero32, 'platform-v1').publicKey),
    },
  ],

  webhook_envelope: [
    {
      name: 'envelope concatenation',
      timestamp: ts,
      body_utf8: body,
      expect_envelope_hex: webhook.envelope(ts, body).toString('hex'),
    },
  ],

  webhook_hmac: [
    {
      name: 'HMAC-SHA-256 over envelope',
      secret_utf8: hmacSecret,
      timestamp: ts,
      body_utf8: body,
      expect_hmac_hex: webhook.hmacHex(hmacSecret, ts, body),
    },
  ],

  webhook_hybrid_roundtrip: [
    {
      name: 'sign + verify with platform keypair from zero master',
      master_hex: zero32.toString('hex'),
      info: 'platform-v1',
      timestamp: ts,
      body_utf8: body,
      hmac_secret_utf8: hmacSecret,
      expect_hmac_ok: true,
      expect_pq_ok: true,
      expect_timestamp_ok_when_fresh: true,
    },
  ],
}

console.log(JSON.stringify(vectors, null, 2))
