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
// Receivers can verify either or both; verifying both is defence-in-depth.

import { createHmac, timingSafeEqual } from 'node:crypto'
import { sign as mlDsaSign, verify as mlDsaVerify } from './ml-dsa.js'

/**
 * Build the canonical signed envelope: timestamp + "." + raw body string.
 *
 * @param {string|number} timestamp  — Unix seconds (string or number)
 * @param {string|Buffer} rawBody    — the EXACT request body as transmitted
 * @returns {Buffer}
 */
export function envelope(timestamp, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8')
  return Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), body])
}

/**
 * Compute the hex HMAC-SHA-256 of the envelope using a shared secret.
 *
 * @returns {string} hex-encoded HMAC (no `sha256=` prefix)
 */
export function hmacHex(secret, timestamp, rawBody) {
  return createHmac('sha256', secret).update(envelope(timestamp, rawBody)).digest('hex')
}

/**
 * Verify the HMAC signature in constant time. The signature header may be
 * passed with or without the `sha256=` prefix.
 *
 * @returns {boolean}
 */
export function verifyHmac(secret, timestamp, rawBody, sigHeader) {
  const expected = 'sha256=' + hmacHex(secret, timestamp, rawBody)
  const given = sigHeader.startsWith('sha256=') ? sigHeader : `sha256=${sigHeader}`
  const a = Buffer.from(expected)
  const b = Buffer.from(given)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/**
 * Produce the X-KXCO-PQ-Signature header value: the hex ML-DSA-65 signature
 * over the envelope, prefixed with `ml-dsa-65=`.
 */
export function pqSign(secretKey, timestamp, rawBody) {
  const sig = mlDsaSign(secretKey, envelope(timestamp, rawBody))
  return `ml-dsa-65=${sig}`
}

/**
 * Verify a hex ML-DSA-65 signature header. Accepts the value with or
 * without the `ml-dsa-65=` prefix.
 *
 * @returns {boolean}
 */
export function verifyPq(publicKey, timestamp, rawBody, sigHeader) {
  const hex = sigHeader.startsWith('ml-dsa-65=')
    ? sigHeader.slice('ml-dsa-65='.length)
    : sigHeader
  return mlDsaVerify(publicKey, envelope(timestamp, rawBody), hex)
}

/**
 * Sign a webhook delivery. Returns the full set of headers a sender should
 * attach to the HTTP request. The caller is responsible for sending the
 * `rawBody` byte-for-byte unchanged (no re-stringification on the receiver).
 *
 * @param {object} args
 * @param {string|Buffer} args.rawBody
 * @param {string|Buffer} args.hmacSecret
 * @param {Buffer|Uint8Array} args.pqSecretKey
 * @param {string} args.pqKid             — fingerprint of the matching public key
 * @param {string} [args.event]           — optional event name
 * @param {string} [args.deliveryId]      — optional idempotency / debugging ID
 * @returns {object} HTTP header map
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
 * Verify a webhook delivery on the receiving side. Both signatures are
 * checked; the result tells you which (or both) passed. Also enforces a
 * timestamp window to prevent replays.
 *
 * @param {object} args
 * @param {object} args.headers           — case-insensitive lookups OK if normalised
 * @param {string|Buffer} args.rawBody    — the EXACT body byte-for-byte
 * @param {string|Buffer} [args.hmacSecret]
 * @param {Buffer|Uint8Array} [args.pqPublicKey]
 * @param {string}  [args.pinnedKid]      — required if pqPublicKey is given
 * @param {number}  [args.windowSeconds]  — default 300 (5 minutes)
 * @returns {{ hmacOk: boolean, pqOk: boolean, timestampOk: boolean, kidOk: boolean }}
 */
export function verifyDelivery({ headers, rawBody, hmacSecret, pqPublicKey, pinnedKid, windowSeconds = 300 }) {
  const ts        = headers['x-kxco-timestamp']
  const sigHmac   = headers['x-kxco-signature']
  const sigPq     = headers['x-kxco-pq-signature']
  const kid       = headers['x-kxco-pq-kid']

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
