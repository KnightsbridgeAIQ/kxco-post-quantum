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
import { sign as mlDsa87Sign, verify as mlDsa87Verify } from './ml-dsa-87.js'

// The PQ signature header names its parameter set: `ml-dsa-65=<hex>`, or
// `ml-dsa-87=<hex>` for an ML-DSA-87 key. The key decides which: an ML-DSA-87
// key (4896-byte secret, 2592-byte public) signs and verifies the -87 form,
// and every other key the -65 form, exactly as before -87 existed. A header
// whose prefix names the other set fails, so a key is never checked as the
// set it is not.
const ML_DSA_65 = { prefix: 'ml-dsa-65=', sign: mlDsaSign, verify: mlDsaVerify }
const ML_DSA_87 = { prefix: 'ml-dsa-87=', sign: mlDsa87Sign, verify: mlDsa87Verify }
const ML_DSA_87_SECRET_KEY_BYTES = 4896
const ML_DSA_87_PUBLIC_KEY_BYTES = 2592
const ML_DSA_65_PUBLIC_KEY_BYTES = 1952

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
function headerString(value) {
  return typeof value === 'string' ? value : undefined
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
 * Produce the X-KXCO-PQ-Signature header value: `ml-dsa-65=<hex>`, or
 * `ml-dsa-87=<hex>` when `secretKey` is an ML-DSA-87 key.
 */
export function pqSign(secretKey, timestamp, rawBody) {
  const set = secretKey?.length === ML_DSA_87_SECRET_KEY_BYTES ? ML_DSA_87 : ML_DSA_65
  const sig = set.sign(secretKey, envelope(timestamp, rawBody))
  return `${set.prefix}${sig}`
}

/**
 * Verify a hex ML-DSA signature header under the set `publicKey` belongs to.
 *
 * An ML-DSA-65 key takes `ml-dsa-65=<hex>` or, as it always has, the bare hex.
 * An ML-DSA-87 key takes only `ml-dsa-87=<hex>`. A prefix naming the other set
 * is false.
 */
export function verifyPq(publicKey, timestamp, rawBody, sigHeader) {
  const is87 = publicKey?.length === ML_DSA_87_PUBLIC_KEY_BYTES
  // A key of neither set's size is refused here, not left to the primitive.
  if (!is87 && publicKey?.length !== ML_DSA_65_PUBLIC_KEY_BYTES) return false
  const set = is87 ? ML_DSA_87 : ML_DSA_65
  // Only the key's own prefix is stripped. A header naming the other set is
  // then neither that prefix nor bare hex, and fails.
  if (sigHeader.startsWith(set.prefix)) {
    return set.verify(publicKey, envelope(timestamp, rawBody), sigHeader.slice(set.prefix.length))
  }
  if (is87) return false
  return set.verify(publicKey, envelope(timestamp, rawBody), sigHeader)
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
  // Each header is read only as a string. Some frameworks hand a repeated
  // header over as an array; that counts as missing rather than being coerced,
  // so a header of any other type fails its check instead of throwing.
  const ts      = headerString(headers['x-kxco-timestamp'])
  const sigHmac = headerString(headers['x-kxco-signature'])
  const sigPq   = headerString(headers['x-kxco-pq-signature'])
  const kid     = headerString(headers['x-kxco-pq-kid'])

  // Both signatures cover the header exactly as it arrives, so it is read
  // only as the decimal digits it is specified to be. parseInt alone would
  // take the leading digits of `1700000000.{"a":1` and leave the rest of the
  // header to be signed, which lets the start of a body move into it.
  const tsNum = /^[0-9]+$/.test(ts) ? parseInt(ts, 10) : NaN
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
