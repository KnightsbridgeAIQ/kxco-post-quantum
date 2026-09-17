// Minimal ACVP client for the NIST ACVTS Demo server.
//
// Credentials live outside this repository, in C:\Users\ADMIN\.credentials\acvts\,
// and nothing here ever writes them to disk or to a log. NIST's covering letter
// is explicit that the certificate, private key and TOTP seed are each secret.
//
// The one trap worth carrying: a TOTP value is accepted ONCE. A second login
// inside the same 30-second window returns HTTP 200 with no accessToken in the
// body, which reads exactly like a broken credential. login() waits for the
// next window rather than reporting a failure.

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { Agent, request } from 'node:https'
import { join } from 'node:path'

const CRED = process.env.ACVTS_CRED_DIR ?? 'C:/Users/ADMIN/.credentials/acvts'
const HOST = process.env.ACVTS_HOST ?? 'demo.acvts.nist.gov'

const cert = readFileSync(join(CRED, 'KXCO_Shayne_Heffernan_Demo.cer'))
const key = readFileSync(join(CRED, 'KXCO_Shayne_Heffernan_Demo.key'))
const seed = Buffer.from(readFileSync(join(CRED, 'KXCO_Shayne_Heffernan_Demo_totp.txt'), 'utf8').trim(), 'base64')

// keepAlive is OFF deliberately. SLH-DSA key generation and signing run for
// minutes between calls, and a pooled socket is long dead by the time the next
// request reuses it: the failure arrives as ECONNRESET "socket hang up" on a
// POST that never left, which reads like the server rejecting us. A fresh TLS
// handshake per call costs milliseconds and removes the whole failure mode.
const agent = new Agent({ cert, key, keepAlive: false })

export const ACV_VERSION = '1.0'

// HMAC-SHA256, 30-second step, 8 digits, dynamic truncation. SHA-1 and the
// 6-digit variant were tried as controls against the live server and refused.
function totp(atMs = Date.now()) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / 30)))
  const mac = createHmac('sha256', seed).update(counter).digest()
  const offset = mac[mac.length - 1] & 0x0f
  const code = mac.readUInt32BE(offset) & 0x7fffffff
  return String(code % 100_000_000).padStart(8, '0')
}

export async function call(path, opts = {}) {
  // A transient reset on a long-running session should not throw away work that
  // took minutes to compute. Retry the request itself, three times, backing off.
  let last
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await once(path, opts)
    } catch (err) {
      last = err
      if (attempt < 3) await new Promise((r) => setTimeout(r, attempt * 5000))
    }
  }
  throw last
}

function once(path, { method = 'GET', body, token } = {}) {
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body))
  const headers = {}
  if (payload) {
    headers['Content-Type'] = 'application/json'
    headers['Content-Length'] = payload.length
  }
  if (token) headers.Authorization = `Bearer ${token}`

  return new Promise((resolve, reject) => {
    const req = request({ host: HOST, path, method, headers, agent, timeout: 180_000 }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }))
    })
    req.on('timeout', () => req.destroy(new Error(`timeout ${method} ${path}`)))
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export async function login({ attempts = 4 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const r = await call('/acvp/v1/login', {
      method: 'POST',
      body: [{ acvVersion: ACV_VERSION }, { password: totp() }],
    })
    if (r.status === 200) {
      const merged = Object.assign({}, ...JSON.parse(r.body).filter((o) => o && typeof o === 'object'))
      if (merged.accessToken) return merged.accessToken
    }
    // Same TOTP window, or a transient. Wait for the next window and retry.
    process.stderr.write(`login attempt ${i + 1}: HTTP ${r.status}, no token, waiting for the next TOTP window\n`)
    await sleep(31_000)
  }
  throw new Error('ACVTS login failed')
}

// A session JWT expires on a clock, not on idleness, and SLH-DSA signing can
// run past it: 624 signatures took long enough that the submit came back 401
// with "The provided JWT expired". The renewal is a login that carries the dead
// token alongside a fresh TOTP, and it returns a token still bound to the
// session. Without this, an hour of computation is thrown away on the last call.
export async function refresh(expiredToken, { attempts = 4 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const r = await call('/acvp/v1/login', {
      method: 'POST',
      body: [{ acvVersion: ACV_VERSION }, { password: totp(), accessToken: expiredToken }],
    })
    if (r.status === 200) {
      const merged = Object.assign({}, ...JSON.parse(r.body).filter((o) => o && typeof o === 'object'))
      if (merged.accessToken) return merged.accessToken
    }
    process.stderr.write(`refresh attempt ${i + 1}: HTTP ${r.status}, waiting for the next TOTP window\n`)
    await sleep(31_000)
  }
  throw new Error('ACVTS token refresh failed')
}

// Every ACVP body is [{acvVersion}, payload]. Fold it to the payload.
export function payloadOf(text) {
  const parsed = JSON.parse(text)
  if (!Array.isArray(parsed)) return parsed
  return Object.assign({}, ...parsed.filter((o) => o && typeof o === 'object' && !('acvVersion' in o)))
}
