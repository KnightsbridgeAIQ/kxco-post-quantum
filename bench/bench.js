// Micro-benchmark: how many KXCO webhook deliveries can this machine
// sign + verify per second?
//
// Run:  node bench/bench.js
// Optional: BENCH_N=10000 node bench/bench.js
//
// Reports: ops/sec for envelope, hmac, ml-dsa sign, ml-dsa verify, and the
// full hybrid signDelivery + verifyDelivery round-trip.

import { randomBytes, createHmac } from 'node:crypto'
import {
  mlDsa, fingerprint, webhook,
} from '../src/index.js'

const N = parseInt(process.env.BENCH_N || '1000', 10)
const master = randomBytes(32)
const { publicKey, secretKey } = mlDsa.keypairFromMaster(master, 'bench-v1')
const kid = fingerprint(publicKey)
const hmacSecret = randomBytes(32)
const body = JSON.stringify({ event: 'payment.settled', amount: 1000, ref: 'INV-2026-001' })

function time(label, n, fn) {
  // warm-up
  for (let i = 0; i < Math.min(50, n); i++) fn()
  const start = process.hrtime.bigint()
  for (let i = 0; i < n; i++) fn()
  const ns = Number(process.hrtime.bigint() - start)
  const ms = ns / 1e6
  const ops = (n / (ms / 1000)).toFixed(0)
  const per = (ms / n).toFixed(3)
  console.log(`  ${label.padEnd(38)}  ${String(ops).padStart(10)} ops/s   ${per.padStart(8)} ms/op`)
}

console.log(`kxco-post-quantum bench — N=${N}`)
console.log(`Node ${process.version} on ${process.platform}/${process.arch}`)
console.log('')

const ts = '1748000000'
time('envelope construction',          N * 100, () => webhook.envelope(ts, body))
time('HMAC-SHA-256 sign',              N * 10,  () => webhook.hmacHex(hmacSecret, ts, body))
time('HMAC-SHA-256 verify',            N * 10,  () => webhook.verifyHmac(hmacSecret, ts, body, 'sha256=' + webhook.hmacHex(hmacSecret, ts, body)))
time('ML-DSA-65 sign',                 N,       () => mlDsa.sign(secretKey, webhook.envelope(ts, body)))

const sigHex = mlDsa.sign(secretKey, webhook.envelope(ts, body))
time('ML-DSA-65 verify',               N,       () => mlDsa.verify(publicKey, webhook.envelope(ts, body), sigHex))

time('hybrid signDelivery (full)',     N,       () => webhook.signDelivery({
  rawBody:     body,
  hmacSecret:  hmacSecret,
  pqSecretKey: secretKey,
  pqKid:       kid,
}))

const fullHeaders = webhook.signDelivery({
  rawBody:     body,
  hmacSecret:  hmacSecret,
  pqSecretKey: secretKey,
  pqKid:       kid,
})
const lowerHeaders = Object.fromEntries(Object.entries(fullHeaders).map(([k, v]) => [k.toLowerCase(), v]))
time('hybrid verifyDelivery (full)',   N,       () => webhook.verifyDelivery({
  headers:     lowerHeaders,
  rawBody:     body,
  hmacSecret:  hmacSecret,
  pqPublicKey: publicKey,
  pinnedKid:   kid,
}))

console.log('')
console.log('Tip: most receivers only need verifyDelivery — that is the rate to size against.')
