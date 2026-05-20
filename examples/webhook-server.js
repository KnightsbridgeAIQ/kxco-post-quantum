// Minimal Express receiver verifying a hybrid-signed KXCO webhook.
// Run: node examples/webhook-server.js

import express from 'express'
import { webhook } from '@kxco/post-quantum'

const app = express()

// IMPORTANT: capture the raw body byte-for-byte. JSON.parse + re-stringify
// will change whitespace and break signature verification.
app.use(express.raw({ type: 'application/json' }))

// Pin once on first integration, then verify offline forever.
const PINNED_KID    = process.env.KXCO_PUBLIC_KID
const PINNED_PUBKEY = Buffer.from(process.env.KXCO_PUBLIC_KEY_HEX, 'hex')
const HMAC_SECRET   = process.env.KXCO_WEBHOOK_SECRET

app.post('/webhooks/kxco', (req, res) => {
  const headers = Object.fromEntries(
    Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), v])
  )

  const r = webhook.verifyDelivery({
    headers,
    rawBody:     req.body,
    hmacSecret:  HMAC_SECRET,
    pqPublicKey: PINNED_PUBKEY,
    pinnedKid:   PINNED_KID,
  })

  if (!r.timestampOk) return res.status(401).json({ error: 'stale timestamp' })
  if (!r.kidOk)       return res.status(401).json({ error: 'unknown kid' })
  if (!r.hmacOk && !r.pqOk) return res.status(401).json({ error: 'invalid signature' })

  const event = JSON.parse(req.body.toString('utf8'))
  console.log('verified event:', event)
  res.json({ ok: true })
})

app.listen(3000, () => console.log('webhook receiver on :3000'))
