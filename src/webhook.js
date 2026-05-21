// Hybrid HMAC + ML-DSA-65 webhook signing — the production pattern used by
// KXCO Bank, KnightsVault, and every product on the KXCO platform.
//
// Why hybrid?
//   - HMAC-SHA-256 is symmetric and post-quantum secure as a MAC. Receivers
//     who share the secret can verify offline with no library dependencies.
//   - ML-DSA-65 adds NON-REPUDIATION: a receiver who only verifies the PQ
//     signature can prove the message came from the holder of the platform
//     private key — even if the HMAC secret has been leaked to a third party.
//
// Both signatures cover EXACTLY the same envelope: `${timestamp}.${rawBody}`.
//
// Isomorphic: HMAC and SHA-256 come from @noble/hashes, constant-time
// compare is a portable byte loop. No node:crypto dependency. Runs in Node
// and modern browsers.

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { sign as mlDsaSign, verify as mlDsaVerify } from './ml-dsa.js'

const HAS_BUFFER = typeof Buffer !== 'undefined'
const enc = new TextEncoder()

function toBytes(input) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') return enc.encode(input)
  throw new Error('expected Uint8Array or string')
}
function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}
function wrap(bytes) {
  return HAS_BUFFER ? Buffer.from(bytes) : bytes
}
// Portable constant-time string compare (Node + browser).
function constTimeEqualStrings(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/**
 * Build the canonical signed envelope: timestamp + "." + raw body string.
 */
export function envelope(timestamp, rawBody) {
  const bodyBytes = toBytes(rawBody)
  const prefixBytes = enc.encode(`${timestamp}.`)
  const out = new Uint8Array(prefixBytes.length + bodyBytes.length)
  out.set(prefixBytes, 0)
  out.set(bodyBytes, prefixBytes.length)
  return wrap(out)
}

/**
 * Compute the hex HMAC-SHA-256 of the envelope using a shared secret.
 */
export function hmacHex(secret, timestamp, rawBody) {
  const env = envelope(timestamp, rawBody)
  const envBytes = env instanceof Uint8Array ? env : new Uint8Array(env)
  const key = toBytes(secret)
  return bytesToHex(hmac(sha256, key, envBytes))
}

/**
 * Verify the HMAC signature in constant time.
 */
export function verifyHmac(secret, timestamp, rawBody, sigHeader) {
  const expected = 'sha256=' + hmacHex(secret, timestamp, rawBody)
  const given = sigHeader.startsWith('sha256=') ? sigHeader : `sha256=${sigHeader}`
  return constTimeEqualStrings(expected, given)
}

/**
 * Produce the X-KXCO-PQ-Signature header value.
 */
export function pqSign(secretKey, timestamp, rawBody) {
  const sig = mlDsaSign(secretKey, envelope(timestamp, rawBody))
  return `ml-dsa-65=${sig}`
}

/**
 * Verify a hex ML-DSA-65 signature header.
 */
export function verifyPq(publicKey, timestamp, rawBody, sigHeader) {
  const hex = sigHeader.startsWith('ml-dsa-65=')
    ? sigHeader.slice('ml-dsa-65='.length)
    : sigHeader
  return mlDsaVerify(publicKey, envelope(timestamp, rawBody), hex)
}

/**
 * Sign a webhook delivery. Returns the full set of headers a sender should
 * attach to the HTTP request.
 */
export function signDelivery({ rawBody, hmacSecret, pqSecretKey, pqKid, event, deliveryId }) {
  const ts = Math.floor(Date.now() / 1000).toString()
  const headers = {
    'Content-Type':        'application/json',
    'X-KXCO-Timestamp':    ts,
    'X-KXCO-Signature':    'sha256=' + hmacHex(hmacSecret, ts, rawBody),
    'X-KXCO-PQ-Signature': pqSign(pqSecretKey, ts, rawBody),
    'X-KXCO-PQ-Kid':       pqKid,
  }
  if (event)      headers['X-KXCO-Event']    = event
  if (deliveryId) headers['X-KXCO-Delivery'] = deliveryId
  return headers
}

/**
 * Verify a webhook delivery on the receiving side.
 */
export function verifyDelivery({ headers, rawBody, hmacSecret, pqPublicKey, pinnedKid, windowSeconds = 300 }) {
  const ts      = headers['x-kxco-timestamp']
  const sigHmac = headers['x-kxco-signature']
  const sigPq   = headers['x-kxco-pq-signature']
  const kid     = headers['x-kxco-pq-kid']

  const tsNum = parseInt(ts, 10)
  const timestampOk = Number.isFinite(tsNum) &&
    Math.abs(Date.now() / 1000 - tsNum) <= windowSeconds

  const hmacOk = (hmacSecret && sigHmac && timestampOk)
    ? verifyHmac(hmacSecret, ts, rawBody, sigHmac)
    : false

  const kidOk = pinnedKid ? kid === pinnedKid : true
  const pqOk = (pqPublicKey && sigPq && timestampOk && kidOk)
    ? verifyPq(pqPublicKey, ts, rawBody, sigPq)
    : false

  return { hmacOk, pqOk, timestampOk, kidOk }
}
