# kxco-post-quantum

**NIST post-quantum signatures and key exchange for Node.js and the browser, proven against NIST's own test vectors.**

[![npm](https://img.shields.io/npm/v/kxco-post-quantum?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum)
[![downloads](https://img.shields.io/npm/dm/kxco-post-quantum?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](./CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-post-quantum)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/KnightsbridgeAIQ/kxco-post-quantum/badge)](https://securityscorecards.dev/viewer/?uri=github.com/KnightsbridgeAIQ/kxco-post-quantum)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/ci.yml)
[![conformance](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/conformance.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/conformance.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

- **All three NIST standards.** ML-DSA-87 and ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203) and SLH-DSA-SHA2-192s (FIPS 205). ML-DSA-87 is the signature set for new keys, and ML-DSA-65 stays for keys that already exist.
- **The CNSA 2.0 parameter sets ship.** ML-DSA-87 and ML-KEM-1024 at Category 5, with the same API as the Category 3 sets.
- **1,793 NIST ACVP vectors passed, 0 failed.** The other 310 are pairings the library refuses as weaker than the parameter set. See [CONFORMANCE.md](./CONFORMANCE.md).
- **Interoperable by test.** 225 checks against liboqs, Bouncy Castle and the Python reference implementations, in both directions, 0 failed. See [CONFORMANCE.md](./CONFORMANCE.md).
- **Native speed on Node 24.** The maths runs in OpenSSL 3.5 on Node 24 and later, and in JavaScript on Node 22 and in browsers, with identical bytes on the wire.
- **Speaks the formats your stack already parses.** Compact JWS and AKP JWK under the `ML-DSA-87` and `ML-DSA-65` algorithm names, and PKCS#8 seed-form keys.
- **A supply chain you can check.** Reproducible builds verified in CI, with SLSA provenance and a CycloneDX SBOM on every release since 1.4.1. Apache-2.0, with no licence check and nothing that phones home.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

**Each requirement has an export.**

| The requirement | What answers it |
|---|---|
| Post-quantum key establishment by 31 Dec 2030, EO 14412 s.4(b)(ii) | `mlKem.encapsulate` and `mlKem.decapsulate`, ML-KEM-768 |
| Post-quantum signatures by 31 Dec 2031, EO 14412 s.4(b)(iii) | `mlDsa87.sign` and `mlDsa87.verify`, ML-DSA-87 |
| "PQC-agile libraries for all new applications", OMB M-26-15 | `mlDsa87` and `mlKem1024` behind the same API: Category 5 is a change of import |
| "API gateways and application workloads must be configured to issue and validate PQC-signed tokens", OMB M-26-15 | `jws.signJws` and `jws.verifyJws`: compact JWS under ML-DSA-87 or ML-DSA-65, algorithm pinned at the verifier |
| "re-encrypting long-lived sensitive data using keys protected by PQC mechanisms", OMB M-26-15 | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Minimum elements for a cryptographic bill of materials, in CISA guidance due by 19 Mar 2027, EO 14412 s.5(d) | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) `--cbom`: a CycloneDX 1.6 CBOM today, ready to check against those elements when CISA publishes them |

**TLS has already moved, so this is the rest.** A stock Node.js client on 22.23.3, 24.21.0 and 26.1.0 negotiates X25519MLKEM768, the hybrid of X25519 and ML-KEM-768, with no options set (measured 30 September 2026). What TLS never reaches is what your application signs, issues and stores, and that is this package. The walkthrough, with every block run against this package: [The 2030 Post-Quantum Deadline in Code](https://www.livetradingnews.com/the-2030-post-quantum-deadline-in-code-6-changes-and-the-test-for-each).

This is the primitive layer every other `kxco-pq-*` package builds on.

[Conformance](./CONFORMANCE.md) · [Benchmarks](./BENCHMARKS.md) · [Migration](./MIGRATION.md) · [Threat model](./THREAT-MODEL.md) · [Changelog](./CHANGELOG.md) · [For institutions](#for-institutions) · [kxco.ai](https://kxco.ai)

---

## Install

```bash
npm install kxco-post-quantum
```

Requires Node.js 22.12+. CI tests every change on Node 22, 24 and 26. ESM-only.

---

## Quick start

```js
import { mlDsa87, mlKem, slhDsa, fingerprint, kidEquals } from 'kxco-post-quantum'

// ML-DSA-87: sign and verify
const { publicKey, secretKey } = mlDsa87.keypairFromMaster(masterSecret, 'signing-87-v1')
const sig = mlDsa87.sign(secretKey, 'hello')
const ok  = mlDsa87.verify(publicKey, 'hello', sig)  // true

// SLH-DSA-SHA2-192s: hash-based signatures (same API shape as mlDsa87)
const slh = slhDsa.keypairFromMaster(masterSecret, 'signing-slh-v1')
const slhSig = slhDsa.sign(slh.secretKey, 'hello')
const slhOk  = slhDsa.verify(slh.publicKey, 'hello', slhSig)  // true

// Key fingerprint
const kid = fingerprint(publicKey)  // e.g. '4a7c9e2f1b3d5680'
kidEquals(kid, kid)                 // true (constant-time)

// ML-KEM-768: key encapsulation
const kemKeys = mlKem.keypairFromMaster(masterSecret, 'encryption-v1')
const { ciphertext, sharedSecret } = mlKem.encapsulate(kemKeys.publicKey)
const recovered = mlKem.decapsulate(ciphertext, kemKeys.secretKey)
// sharedSecret and recovered are the same 32 bytes
```

`masterSecret` is a Node Buffer or typed array (Uint8Array) with at least 16 bytes of entropy (typically 32–64 bytes from an env var or KMS).

**One label per key.** The label is the domain separation: one master under one label yields the same seed bytes, whichever parameter set reads them. Give every parameter set and every purpose its own label, as above, and version it (`-v1`, `-v2`) so a rotation is a new label.

### Category 5 parameter sets

`mlDsa87` (ML-DSA-87) is the signature set for new keys. `mlDsa` (ML-DSA-65) has
the same API, one security category lower, and stays for the keys that already
exist, whose signatures keep verifying. `mlKem1024` (ML-KEM-1024) has the same
API as `mlKem`, one security category higher. Reach for it when a counterparty
specifies Category 5 or names the parameter set.

```js
import { mlDsa87, mlKem1024 } from 'kxco-post-quantum'

const { publicKey, secretKey } = mlDsa87.keypairFromMaster(masterSecret, 'signing-87-v1')
const sig = mlDsa87.sign(secretKey, 'hello')      // 4627 bytes, 9254 hex chars
mlDsa87.verify(publicKey, 'hello', sig)           // true
```

| | Category 5 | Category 3 |
|---|---|---|
| Signatures | `mlDsa87`: pk 2592, sig 4627, for new keys | `mlDsa`: pk 1952, sig 3309, for existing keys |
| Key encapsulation | `mlKem1024`: pk 1568, ct 1568 | `mlKem`: pk 1184, ct 1088 |

The two sets do not mix, deliberately. Default derivation info differs, so one
master yields unrelated keys for each, and so does a distinct label of your own;
a signature from one set does not verify under the other. Sizes are the migration cost, so check any fixed-width
signature or key field before mixing sets in one system.

**CNSA 2.0 names ML-DSA-87 and ML-KEM-1024**, so moving a deployment to the
CNSA 2.0 parameter sets is a change of import. See
[CONFORMANCE.md](./CONFORMANCE.md).

### Context strings (FIPS 204 / FIPS 205)

`sign` and `verify` take an optional context string, at most 255 bytes. A
signature made under a context does not verify without it, or under a different
one.

```js
const sig = mlDsa87.sign(secretKey, 'hello', { context: 'kxco-nexus-v1' })

mlDsa87.verify(publicKey, 'hello', sig, { context: 'kxco-nexus-v1' })  // true
mlDsa87.verify(publicKey, 'hello', sig)                                // false
mlDsa87.verify(publicKey, 'hello', sig, { context: 'other-v1' })       // false
```

The parameter is optional and defaults to no context, so every existing call
site is unaffected. An empty context is identical to omitting it. `mlDsa` and
`slhDsa` take the same option.

**Context separates at the signature level; `keypairFromMaster(master, info)`
separates at the key level.** They are complementary. Use a context when one key
legitimately signs for several purposes and you need a signature from one
purpose to be unusable in another. Use a distinct derived key when the purposes
should not share a key at all.

Strings are encoded as UTF-8, so the 255-byte limit is bytes and not
characters. Over-length or wrongly typed input throws (`RangeError` /
`TypeError`) rather than returning `false`, because that is a caller bug and not
a bad signature:

```js
mlDsa87.sign(secretKey, 'hello', 'kxco-nexus-v1')  // throws TypeError
                                                   // (needs { context: ... })
```

That last case is worth guarding: without the throw it would silently sign with
*no* context and produce a valid-looking signature carrying none of the intended
separation.

---

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in [LICENCE-PRODUCT.md](./LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

---

## API

### `mlDsa87`: ML-DSA-87 signatures (NIST FIPS 204)

The signature set for new keys. Security Category 5.

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey, seed }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'ml-dsa-87-v1'`. `seed` is the 32 bytes the pair was expanded from. See [`seed`](#seed-seed-form-keys-rfc-9964-lamps). |
| `sign` | `(secretKey, message) → string` | Signs a message. Returns a hex-encoded signature (9254 chars). |
| `verify` | `(publicKey, message, sigHex) → boolean` | Verifies a hex-encoded signature. Returns `false` on any failure. |
| `ml_dsa87` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 2592 bytes. `secretKey` is 4896 bytes. `message` accepts `Buffer`, `Uint8Array`, or `string`.

### `mlDsa`: ML-DSA-65 signatures (NIST FIPS 204)

The ML-DSA-65 namespace, kept for keys that already exist. Same API as
`mlDsa87`, at Security Category 3. Its name and exports are unchanged, and every
signature it has made keeps verifying.

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey, seed }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'ml-dsa-65-v1'`. `seed` is the 32 bytes the pair was expanded from. See [`seed`](#seed-seed-form-keys-rfc-9964-lamps). |
| `sign` | `(secretKey, message) → string` | Signs a message. Returns a hex-encoded signature (6618 chars). |
| `verify` | `(publicKey, message, sigHex) → boolean` | Verifies a hex-encoded signature. Returns `false` on any failure. |
| `ml_dsa65` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 1952 bytes. `secretKey` is 4032 bytes. `message` accepts `Buffer`, `Uint8Array`, or `string`.

### `slhDsa`: SLH-DSA-SHA2-192s signatures (NIST FIPS 205)

Hash-based, stateless signatures. Security Category 3 (matching ML-DSA-65), with security resting only on the SHA-2 hash function: no lattice or number-theoretic assumptions. Use it as a conservative hedge alongside `mlDsa87`. Signatures are 16,224 bytes against 4,627 for ML-DSA-87 and 3,309 for ML-DSA-65, per [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), so ML-DSA stays the choice for high-volume signing.

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'slh-dsa-sha2-192s-v1'`. |
| `sign` | `(secretKey, message) → string` | Signs a message. Returns a hex-encoded signature (32448 chars). |
| `verify` | `(publicKey, message, sigHex) → boolean` | Verifies a hex-encoded signature. Returns `false` on any failure. |
| `slh_dsa_sha2_192s` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 48 bytes. `secretKey` is 96 bytes. `message` accepts `Buffer`, `Uint8Array`, or `string`.

### `mlKem`: ML-KEM-768 key encapsulation (NIST FIPS 203)

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey, seed }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'ml-kem-768-v1'`. `seed` is the 64 bytes the pair was expanded from. |
| `encapsulate` | `(publicKey) → { ciphertext, sharedSecret }` | Generates a shared secret and ciphertext to send to the key holder. |
| `decapsulate` | `(ciphertext, secretKey) → Buffer` | Recovers the shared secret from a ciphertext. Returns 32 bytes. |
| `ml_kem768` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 1184 bytes. `ciphertext` is 1088 bytes. `sharedSecret` is 32 bytes.

### `fingerprint(publicKey)` → `string`

First 16 hex characters of SHA-256 of the public key. Stable for the lifetime of the key. Accepts raw bytes or a hex string.

### `kidEquals(a, b)` → `boolean`

Constant-time comparison of two kid strings. Use this when comparing user-supplied input, in place of `===`.

### `deriveSeed(master, info, length)` → `Buffer`

HKDF-SHA-512 derivation. `master` must be at least 16 bytes. `info` is a required domain-separation string. Returns `length` bytes.

### `seed`: seed-form keys (RFC 9964, LAMPS)

FIPS 203 and 204 expand a keypair from a short seed. The expanded private key
this package returns is derived from that seed and does not contain it, so a
seed cannot be recovered from an expanded key. `keypairFromMaster` therefore
returns the seed it derived alongside the pair. That is additive, so callers that
destructure `{ publicKey, secretKey }` are unaffected.

Seed form is 32 bytes for ML-DSA and 64 for ML-KEM. It fits in a KMS secret, an
HSM object or an env var, and it is the only private form an RFC 9964 AKP JWK
accepts.

| Export | Signature | Description |
|---|---|---|
| `SEED_ALGORITHMS` | `string[]` | `ML-DSA-65`, `ML-DSA-87`, `ML-KEM-768`, `ML-KEM-1024`. SLH-DSA has no seed form. |
| `seedFromMaster` | `(alg, master, info?) → bytes` | Same HKDF-SHA-512 derivation `keypairFromMaster` uses, so it reproduces keys already in production. |
| `keypairFromSeed` | `(alg, seed) → { publicKey, secretKey, seed }` | Expands a seed. Byte-identical to what OpenSSL 3.5 derives from the same seed. |
| `exportJwk` | `(alg, { publicKey, seed? }, opts?) → jwk` | RFC 9964 AKP JWK. `priv` carries the seed. |
| `importJwk` | `(jwk) → { alg, publicKey, secretKey?, seed? }` | Rejects a JWK whose seed and `pub` disagree. |
| `exportSeedPkcs8` | `(alg, seed) → bytes` | PKCS#8 in LAMPS seed form, the `[0] IMPLICIT` CHOICE. |
| `importSeedPkcs8` | `(der) → { alg, seed }` | Refuses an expanded-form key rather than truncating it into a seed. |

The encodings are not read off the specification. `test/seed.test.js` asserts
that the DER this package writes is byte-identical to what this machine's
OpenSSL writes, for every parameter set, and skips with a reason where there is
no native backend to compare against.

```js
import { mlDsa87, seed } from 'kxco-post-quantum'

const key = mlDsa87.keypairFromMaster(process.env.KXCO_MASTER_KEY)
const jwk = seed.exportJwk('ML-DSA-87', key, { kid: fingerprint(key.publicKey) })
// { kty: 'AKP', alg: 'ML-DSA-87', pub: '...', priv: '<32-byte seed>', kid: '...' }
```

### `jws`: compact JWS with the RFC 9964 algorithm names

Format only. A token signed here verifies in any process holding the public
key, offline, with no configuration and no licence. RFC 9964 registered
`ML-DSA-87` and `ML-DSA-65` as JWS algorithms so a post-quantum signature can
travel the path an institution's gateway, IdP and partner verifier already
parse.

| Export | Signature | Description |
|---|---|---|
| `signJws` | `(payload, secretKey, opts?) → string` | Compact JWS. Objects are JSON-serialised. Without `opts.alg` the key decides: an ML-DSA-65 secret key signs `ML-DSA-65`, and every other key `ML-DSA-87`, the default. |
| `verifyJws` | `(token, publicKey, opts?) → { valid, ... }` | Fails closed. `{ alg }` and `{ kid }` pin what the header may declare. |
| `decodeJwsHeader` | `(token) → object \| null` | Unauthenticated read, for choosing which key to fetch. |

The algorithm is resolved from an allowlist inside the module, never from the
token, so a token cannot name its own verification routine. `crit` and `b64`
headers are refused rather than ignored, and the public key's length must match
the algorithm the header declares.

The JWS algorithms are ML-DSA-87 and ML-DSA-65, the parameter sets sized for a
request path.

### `backend()` and `isNative(alg)`

Reports which implementation is doing the maths in this process: `openssl`
with its version and parameter sets, or `javascript` with the reason the native
backend is unavailable. For evidence bundles and support tickets. It reports,
and the operator selects, as the next section shows.

### `webhook`: hybrid HMAC + ML-DSA delivery signing

Low-level helpers for the KXCO hybrid webhook pattern: `envelope`, `hmacHex`, `verifyHmac`, `pqSign`, `verifyPq`, `signDelivery`, `verifyDelivery`. HMAC-SHA-256 gives symmetric verification with no library dependency; ML-DSA adds non-repudiation over the same `${timestamp}.${body}` envelope. The full identity/credential surface lives in `kxco-pq-sdk`.

The key decides the PQ header form. An ML-DSA-87 key signs `ml-dsa-87=<hex>`, and an ML-DSA-65 key signs `ml-dsa-65=<hex>` over the same envelope. `verifyPq` and `verifyDelivery` accept only the form that matches the public key they are given: a header whose prefix names the other set fails, and an ML-DSA-87 key takes no bare-hex form.

---

## Requiring the native backend

This package picks its implementation at import time: OpenSSL 3.5 where the
runtime provides the FIPS 203/204/205 primitives, the JavaScript implementation
otherwise. Both produce identical wire bytes, so falling back is the right
default and nothing about a signature changes.

For a deployment under a control that says cryptography must execute inside a
validated module, make the native backend a requirement:

```js
import { requireNativeBackend } from 'kxco-post-quantum'

requireNativeBackend(['ML-DSA-87', 'ML-KEM-768'])
```

It throws `ERR_KXCO_PQ_BACKEND` if the JavaScript backend is live, or if the
OpenSSL present cannot provide a parameter set you named. The error carries
`actual`, `missing` and `available` so a failure says which, rather than only
that.

Operators can enforce it without touching application code, which matters
because the team under the control is usually not the team calling the library:

```
KXCO_PQ_REQUIRE_NATIVE=1
```

Set that and a process which has landed on the JavaScript backend fails at
import, before its first signature rather than after.

**It asserts that OpenSSL is doing the maths** and removes the silent fallback.
Pair it with the validated OpenSSL build your control names, and the control is
enforced at import.

### Pinning the implementation your certificate names

`requireNativeBackend()` only ever asserts OpenSSL. Both implementations are
being taken to algorithm validation, so a deployment under a control that names
a certificate has to be able to pin whichever one its certificate covers, and
for some that is the JavaScript implementation.

```
KXCO_PQ_BACKEND=javascript    never use OpenSSL, even where it is present
KXCO_PQ_BACKEND=openssl       prefer OpenSSL, which is the default anyway
```

```js
import { requireBackend } from 'kxco-post-quantum'

requireBackend('javascript')                            // the JS certificate
requireBackend('openssl', ['ML-DSA-87', 'ML-KEM-768'])  // the native one
```

A value that is neither throws at import, so a misspelled pin is caught before
the first signature.

The environment selects, the function asserts, and they are deliberately kept
apart: `requireBackend('javascript')` fails on an unpinned OpenSSL process
rather than switching it. Application code cannot quietly change which
implementation your evidence is about.

Nothing here changes what a signature looks like. The two produce identical
wire bytes, which the interoperability matrix proves for every parameter set in
both directions, and a signature made under the pin verifies on the other
backend. What changes is which one computed it, and `backend()` always reports
that truthfully, including when the answer is the result of a pin:

```js
backend()
// { kind: 'javascript', library: '@noble/post-quantum', pinned: 'javascript',
//   reason: 'KXCO_PQ_BACKEND=javascript pins this process to the JavaScript backend' }
```

That `reason` keeps pinned and unavailable apart, so an evidence bundle records
exactly which one applied.

## The KXCO post-quantum family

This is the primitive layer: keys, signatures, encapsulation and fingerprints.
Install it directly when you need ML-DSA or ML-KEM on their own, or pick the
package that matches the job.

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

---

## Security

The maths runs in OpenSSL 3.5 on Node 24 and later, and in [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) elsewhere. This package reimplements no NIST primitive. Every parameter set is held to NIST's own ACVP vectors and cross-checked against liboqs, Bouncy Castle and the Python reference implementations on both backends, per [CONFORMANCE.md](./CONFORMANCE.md). The audit history of every upstream library is recorded in [AUDIT.md](./AUDIT.md).

To report a vulnerability: [open a private security advisory](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/security/advisories/new) or email **john@knightsbridgelaw.com**. Acknowledgement within 2 business days, triage decision within 5. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

## Verifying a release

Every claim on this page is checkable without asking us. The evidence bundle
for the current release sits at a permanent, unauthenticated URL:

```bash
# the full evidence bundle for the current release
curl -sLO https://github.com/KnightsbridgeAIQ/kxco-post-quantum/releases/latest/download/evidence-node24.x.zip

# or just the manifest: every file digest, and which backend produced the results
curl -sL  https://github.com/KnightsbridgeAIQ/kxco-post-quantum/releases/latest/download/manifest-node24.x.json

# licence and provenance, straight from the registry
npm view kxco-post-quantum license          # Apache-2.0
npm audit signatures --json                 # assert invalid:0 and missing:0
```

Every release asset is signed with ML-DSA-87 by this package's own signing path,
and carries a SLSA provenance file recording the workflow that built it.

```
manifest-node24.x.json          the bundle's manifest
evidence-node24.x.zip           the bundle
evidence-node24.x.zip.sig       ML-DSA-87 signature over the zip, hex
evidence.intoto.jsonl           SLSA provenance
release-signing-key-87.pub.hex  the ML-DSA-87 public key, also committed to this repository
release-signing-key.pub.hex     the ML-DSA-65 key that signed releases before 1.9.0
```

```js
import { readFileSync } from 'node:fs'
import { mlDsa87 } from 'kxco-post-quantum'

const pub = Buffer.from(readFileSync('release-signing-key-87.pub.hex', 'utf8').trim(), 'hex')
const sig = readFileSync('evidence-node24.x.zip.sig', 'utf8').trim()
mlDsa87.verify(pub, readFileSync('evidence-node24.x.zip'), sig)   // true
```

Compare the public key with the copy committed to this repository, so the key
and the artefact are checked against two independent sources.
