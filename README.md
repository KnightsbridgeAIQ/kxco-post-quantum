# kxco-post-quantum

**Production-tested post-quantum cryptography patterns.** Deterministic key derivation, hybrid webhook signing, and kid fingerprinting — the integration patterns KXCO uses in production across KnightsVault, KXCO Bank, KnightsBot, The Exchequer, and Armature L1.

[![npm](https://img.shields.io/npm/v/kxco-post-quantum?color=d4a017&label=npm)](https://www.npmjs.com/package/kxco-post-quantum)
[![license](https://img.shields.io/npm/l/kxco-post-quantum)](./LICENSE)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-post-quantum)](https://socket.dev/npm/package/kxco-post-quantum)
[![live verifier](https://img.shields.io/website?url=https%3A%2F%2Fchain.kxco.ai%2Fwallet%2Fverify&up_message=live&up_color=brightgreen&down_message=down&down_color=red&label=production)](https://chain.kxco.ai/wallet/verify)

---

## 60-second quickstart

Install the package, fetch a freshly signed test vector from the live KXCO platform, post it back to verify — **200 OK**. The same code path every production webhook runs.

```bash
# 1. Install
npm install kxco-post-quantum

# 2. Fetch a freshly signed test vector from the live KXCO platform
curl -s https://chain.kxco.ai/wallet/api/verify-demo > vector.json

# 3. Post it back — the server verifies HMAC + ML-DSA-65 against the live key
node --input-type=module -e '
  import fs from "node:fs"
  const v = JSON.parse(fs.readFileSync("vector.json", "utf8"))
  const h = v.headers
  const res = await fetch("https://chain.kxco.ai/wallet/api/verify-demo", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      timestamp:  h["X-KXCO-Timestamp"],
      body:       v.body,
      hmacSecret: v.hmacSecret,
      hmacSig:    h["X-KXCO-Signature"],
      pqSig:      h["X-KXCO-PQ-Signature"].replace(/^ml-dsa-65=/, ""),
      pqKid:      h["X-KXCO-PQ-Kid"],
    }),
  })
  console.log(res.status, await res.json())
'
# → 200 { kidMatch: true, hmac: { ok: true }, pq: { ok: true }, ... }
```

The platform signs every fetch fresh — no cached fixtures, no replay. `verify-demo` exposes the HMAC secret for the demo only; in production the HMAC secret never leaves the receiving server.

## Used in production at

This is not a sample library. It runs in production at KXCO across multiple products. You can verify this yourself without any cooperation from us:

```bash
# Fetch the live platform PQ identity key from production
curl https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey

# Returns a JSON document with alg=ML-DSA-65, the public key (3904 hex chars),
# and a kid fingerprint. The kid is fingerprint(publicKey) using this library.
```

The wallet at `chain.kxco.ai` imports `kxco-post-quantum` directly from npm. The platform identity signing module ([src/lib/pqSigner.js in kxco-bank](https://chain.kxco.ai/wallet/dev-docs)) delegates to `mlDsa.keypairFromMaster`, `mlDsa.sign`, and `fingerprint` from this package. Every outbound webhook from the KXCO platform is signed using `webhook.signDelivery`. You can pin the kid returned above, install this library, and verify any webhook from the production fleet offline.

Other KXCO products on the same package: KnightsVault (institutional custody), KnightsBot (universal trading — every order signed), The Exchequer (compliance intelligence), Armature L1 (the permissioned chain underneath everything).

## What this is

A higher-level package that wraps [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — the audited, dependency-free TypeScript reference implementation of NIST's August 2024 post-quantum standards — with the integration patterns we run in production:

- **Deterministic key derivation** from a master secret via HKDF-SHA-512 with domain separation
- **Hybrid HMAC + ML-DSA-65 webhook signing** with non-repudiation
- **Kid fingerprints** for fast key identification in delivery headers
- **Replay protection** through enforced timestamp windows
- **Constant-time comparisons** where it matters

This package does NOT reimplement the NIST primitives. Cryptographic operations defer to `@noble/post-quantum`.

## What it isn't

- Not a TLS library — use OpenSSL 3.5+ or BoringSSL for `X25519MLKEM768` at the edge
- Not a key management service — use AWS KMS, HashiCorp Vault, or an HSM for production secret storage
- Not FIPS 140-3 certified — the underlying algorithms are FIPS-standardised; the *module* is not validated

## Install

```bash
npm install @kxco/post-quantum
```

Requires Node.js 18+. ESM-only.

## Quick start

### Sign a webhook

```js
import { webhook, mlDsa, fingerprint, deriveSeed } from '@kxco/post-quantum'

// Derive a stable platform identity from your master secret
const KXCO_KEY_MASTER = Buffer.from(process.env.KXCO_KEY_MASTER, 'hex')
const { publicKey, secretKey } = mlDsa.keypairFromMaster(KXCO_KEY_MASTER, 'platform-v1')
const pqKid = fingerprint(publicKey)

// On every outbound webhook
const rawBody = JSON.stringify(payload)
const headers = webhook.signDelivery({
  rawBody,
  hmacSecret:  endpointSecret,
  pqSecretKey: secretKey,
  pqKid,
  event:       'payment.settled',
  deliveryId:  jobId,
})

await fetch(url, { method: 'POST', headers, body: rawBody })
```

### Verify a webhook (receiver side)

```js
import { webhook } from '@kxco/post-quantum'

// Pin these from /.well-known/kxco-pq-pubkey on first integration
const PINNED_KID    = '4a7c9e2f1b3d5680'
const PINNED_PUBKEY = Buffer.from('...3904 hex chars...', 'hex')
const HMAC_SECRET   = process.env.KXCO_WEBHOOK_SECRET

const result = webhook.verifyDelivery({
  headers:      req.headers,
  rawBody:      req.rawBody,      // the body bytes EXACTLY as received
  hmacSecret:   HMAC_SECRET,
  pqPublicKey:  PINNED_PUBKEY,
  pinnedKid:    PINNED_KID,
})

if (!result.hmacOk && !result.pqOk) {
  return res.status(401).end()
}
```

### Encapsulate to a recipient

```js
import { mlKem } from '@kxco/post-quantum'

// Sender side — encapsulate to the recipient's public key
const { ciphertext, sharedSecret } = mlKem.encapsulate(recipientPubKey)
// Use sharedSecret as an AES-256-GCM key; transmit ciphertext to the recipient

// Recipient side — recover the same shared secret
const recovered = mlKem.decapsulate(ciphertext, mySecretKey)
```

### Deterministic keypair from a master secret

```js
import { mlDsa, mlKem, deriveSeed } from '@kxco/post-quantum'

const master = Buffer.from(process.env.KXCO_KEY_MASTER, 'hex')

// Two domain-separated keypairs from the same master
const signing    = mlDsa.keypairFromMaster(master, 'platform-signing-v1')
const encryption = mlKem.keypairFromMaster(master, 'platform-encryption-v1')

// You can also derive raw seeds for other purposes
const customSeed = deriveSeed(master, 'audit-trail-anchor-v1', 32)
```

## The signed envelope

Both signatures cover **the exact same envelope**: `timestamp + "." + raw_body`.

```
4a7c9e2f1b3d5680.{"event":"payment.settled","amount":1000}
^^^ Unix seconds  ^^^ raw body, byte-for-byte
```

This means receivers can verify either signature independently. Verifying both is defence-in-depth: HMAC blocks tampering by anyone without the shared secret, while ML-DSA-65 binds the message to the platform identity even if the HMAC secret leaks.

## Why hybrid (HMAC + PQ) instead of PQ-only?

| Concern | HMAC-SHA-256 | ML-DSA-65 |
|---|---|---|
| Symmetric / asymmetric | Symmetric | Asymmetric |
| Post-quantum secure | ✓ | ✓ |
| Verify offline with shared secret | ✓ | — |
| Non-repudiation | ✗ — anyone with the secret can forge | ✓ — only the holder of the private key can sign |
| Library required to verify | none | a FIPS-204 library |
| Signature size | 32 bytes | 3309 bytes |

You get the cheap-and-easy verification path AND cryptographic identity binding. Receivers can adopt one signature first and the other later, or both from day one.

## API

### `mlDsa` — ML-DSA-65 (NIST FIPS 204, Dilithium3)

- `keypairFromMaster(master, info?)` → `{ publicKey, secretKey }`
- `sign(secretKey, message)` → hex string
- `verify(publicKey, message, sigHex)` → boolean
- `ml_dsa65` — the raw `@noble/post-quantum` primitive, re-exported

### `mlKem` — ML-KEM-768 (NIST FIPS 203, Kyber768)

- `keypairFromMaster(master, info?)` → `{ publicKey, secretKey }`
- `encapsulate(publicKey)` → `{ ciphertext, sharedSecret }`
- `decapsulate(ciphertext, secretKey)` → `Buffer`
- `ml_kem768` — the raw `@noble/post-quantum` primitive, re-exported

### `deriveSeed(master, info, length)` → `Buffer`

HKDF-SHA-512 derivation. Empty salt is fine when `master` has high entropy. Domain-separate via `info`.

### `fingerprint(publicKey)` → 16-hex `kid`

First 16 hex characters of SHA-256 of the public key. Stable for the lifetime of the key.

### `kidEquals(a, b)` → boolean

Constant-time string compare. Use this when comparing user-supplied kids.

### `webhook` — hybrid signing utilities

- `envelope(timestamp, rawBody)` → `Buffer`
- `hmacHex(secret, timestamp, rawBody)` → hex string
- `verifyHmac(secret, timestamp, rawBody, sigHeader)` → boolean
- `pqSign(secretKey, timestamp, rawBody)` → `ml-dsa-65=<hex>` header value
- `verifyPq(publicKey, timestamp, rawBody, sigHeader)` → boolean
- `signDelivery({ rawBody, hmacSecret, pqSecretKey, pqKid, ... })` → header map
- `verifyDelivery({ headers, rawBody, hmacSecret?, pqPublicKey?, pinnedKid?, windowSeconds? })` → `{ hmacOk, pqOk, timestampOk, kidOk }`

## Security notes

- **Keep your master secret in environment variables or a KMS / HSM.** Never commit it.
- **Use domain separation.** Two purposes = two distinct `info` strings.
- **Pin the kid.** Don't trust the public key on every request — fetch and pin it once.
- **Receive raw bodies byte-for-byte.** Re-stringifying JSON before verifying changes the signature input.
- **Enforce timestamp windows.** Defaults to 5 minutes. Set lower for higher-security paths.
- **Constant-time compare strings.** Use `kidEquals` and `verifyHmac`, not `===`.

## Reproducibility

Every public output is pinned in `test/vectors.json`. Run them:

```bash
git clone https://github.com/JackKXCO/kxco-post-quantum
cd kxco-post-quantum
npm install
npm test          # 9 functional tests + 29 vector checks
npm run test:vectors   # vectors only
```

Expected output: `✓ All 29 checks pass — library output matches pinned vectors bit-for-bit.`

If any check fails on a release version, file an issue. The vectors are the tripwire for cryptographic regressions.

## Audit posture

See [AUDIT.md](./AUDIT.md) for the full statement. Short version:

- **Underlying primitives** (`@noble/post-quantum@0.2.1`) — audited by Cure53, 2024
- **This wrapper** — no third-party audit yet. Roadmap: external audit Q3 2026, public bug bounty Q4 2026, FIPS 140-3 CMVP application 2027
- **Internal review** — KXCO Engineering + Cybersecurity (lead: Sean O'Coiligh, ex-DTCC Offensive Cyber)
- **Production deployment** — live at chain.kxco.ai since 2025-11

## References

- [NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — the underlying audited implementation
- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)

## About KXCO

KXCO by Knightsbridge is the unification layer for global trade — settlement, issuance, compliance, custody, trading. Quantum-resistant by design. Visit [kxco.ai](https://kxco.ai).

## License

MIT. See [LICENSE](./LICENSE).
