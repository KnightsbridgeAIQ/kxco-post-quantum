# Changelog

All notable changes to `kxco-post-quantum` are documented here. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-05-21

Substance additions to the v1.0 release. No API changes. Same code on the cryptographic path; auditability and reproducibility infrastructure expanded.

### Added
- `AUDIT.md` — self-attested audit posture, including explicit roadmap for third-party review (Q3 2026), bug bounty (Q4 2026), and FIPS 140-3 CMVP application (2027)
- `test/vectors.json` — 29 deterministic test vectors pinning every primitive's output bit-for-bit
- `test/run-vectors.js` — runner that verifies the library's output against `vectors.json` (exit code 0 = match)
- `test/generate-vectors.js` — vector generator (run only when the library's output behaviour changes)
- `npm test` — now runs both functional tests and vector verification
- `npm run test:vectors` — vector check only
- Production deployment proof: the wallet at `chain.kxco.ai` now imports `kxco-post-quantum` directly via npm. Real-world download count starts here.

### Changed
- `SECURITY.md` — sharpened with explicit threat model, in-scope vs out-of-scope responsibilities, pinned `@noble/post-quantum@0.2.1` integrity hash, Cure53 audit reference, FIPS posture clarification, replay-window and side-channel limitations
- `README.md` — added "Used in production at" section with file refs to the live deployment

### Why a patch and not a feature release
No API surface changes. Same exports, same signatures, same behaviour. The diff is documentation, vectors, and infrastructure that lets reviewers verify the library without trusting the publisher.

## [1.0.0] — 2026-05-21

First stable release. The public API below is committed to: future minor and patch releases will not break it without a major version bump.

### Committed public API

```js
import {
  mlDsa,        // namespace
  mlKem,        // namespace
  deriveSeed,
  fingerprint,
  kidEquals,
  webhook,      // namespace
} from 'kxco-post-quantum'
```

| Export | Signature | Notes |
|---|---|---|
| `mlDsa.keypairFromMaster(master, info='ml-dsa-65-v1')` | → `{ publicKey: Buffer, secretKey: Buffer }` | Deterministic. Stable across versions. |
| `mlDsa.sign(secretKey, message)` | → hex string (6618 chars) | `message` accepts Buffer or string |
| `mlDsa.verify(publicKey, message, sigHex)` | → boolean | Catches exceptions, returns false |
| `mlDsa.ml_dsa65` | re-export | Raw `@noble/post-quantum` primitive |
| `mlKem.keypairFromMaster(master, info='ml-kem-768-v1')` | → `{ publicKey, secretKey }` | Deterministic |
| `mlKem.encapsulate(publicKey)` | → `{ ciphertext, sharedSecret, cipherText }` | `cipherText` (camelCase) alias for noble compatibility |
| `mlKem.decapsulate(ciphertext, secretKey)` | → Buffer (32 bytes) | |
| `mlKem.ml_kem768` | re-export | Raw primitive |
| `deriveSeed(master, info, length)` | → Buffer | HKDF-SHA-512 with empty salt; requires `master.length ≥ 16` |
| `fingerprint(publicKey)` | → 16-hex string | First 8 bytes of SHA-256(pubkey) |
| `kidEquals(a, b)` | → boolean | Constant-time string compare |
| `webhook.envelope(timestamp, rawBody)` | → Buffer | `timestamp + "." + rawBody` |
| `webhook.hmacHex(secret, timestamp, rawBody)` | → hex string | HMAC-SHA-256 over envelope |
| `webhook.verifyHmac(secret, timestamp, rawBody, sigHeader)` | → boolean | Constant-time. Accepts `sha256=` prefix. |
| `webhook.pqSign(secretKey, timestamp, rawBody)` | → `ml-dsa-65=<hex>` | Ready-to-send header value |
| `webhook.verifyPq(publicKey, timestamp, rawBody, sigHeader)` | → boolean | Accepts `ml-dsa-65=` prefix |
| `webhook.signDelivery({ rawBody, hmacSecret, pqSecretKey, pqKid, event?, deliveryId? })` | → HTTP header map | Full sender helper |
| `webhook.verifyDelivery({ headers, rawBody, hmacSecret?, pqPublicKey?, pinnedKid?, windowSeconds=300 })` | → `{ hmacOk, pqOk, timestampOk, kidOk }` | Receiver helper. Either signature can be omitted to skip that check. |

### What "committed" means
We will not break any of the above signatures in a 1.x release. We will not change algorithm choices in a 1.x release. We will not change the envelope format `${timestamp}.${rawBody}` in a 1.x release. We may add new exports; existing ones won't move.

### Verified at release
- 9/9 functional tests pass (sign/verify, encapsulate/decapsulate, hybrid delivery, replay rejection, tamper rejection)
- 29/29 test vectors pass
- Underlying primitives: `@noble/post-quantum@0.2.1` (audited by Cure53, 2024)
- Node.js 18+ ESM-only

### Initial release notes
ESM-only. Node.js 18+. FIPS-aligned (implements FIPS 203/204 algorithms). Not CMVP-validated as a module. TLS guidance: use OpenSSL 3.5+ for `X25519MLKEM768` hybrid at the edge — this package does not handle TLS.

## [0.1.0] — 2026-05-21

Initial pre-release. Same surface as 1.0.0; promoted to 1.0.0 after verifying clean install and round-trip on a fresh environment.
