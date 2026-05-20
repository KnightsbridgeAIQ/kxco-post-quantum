# Security Policy

## Reporting a vulnerability

Email **security@kxco.ai** with details. Do not open public GitHub issues for vulnerabilities.

- Acknowledgement within 48 hours
- Initial triage of critical findings within 5 business days
- Coordinated disclosure: we patch first, credit the reporter, publish a CVE / GHSA

## Scope

This package's surface is the **integration patterns**: deterministic key derivation, kid fingerprinting, envelope construction, hybrid HMAC + ML-DSA-65 webhook signing, replay-window enforcement. Vulnerabilities in the **underlying NIST primitives** belong upstream.

| Layer | Where it lives | Where to report |
|---|---|---|
| ML-DSA-65 / ML-KEM-768 algorithm bugs | `@noble/post-quantum` | https://github.com/paulmillr/noble-post-quantum/security |
| HKDF-SHA-512 / HMAC-SHA-256 / SHA-256 | Node.js `crypto` module | https://github.com/nodejs/node/security |
| Integration patterns (this library) | this repo | security@kxco.ai |

## Cryptographic posture

### Algorithms and standards

| Primitive | Standard | Security level |
|---|---|---|
| ML-DSA-65 (Dilithium3) | [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Category 3 (≈ AES-192) |
| ML-KEM-768 (Kyber768) | [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Category 3 (≈ AES-192) |
| HKDF-SHA-512 | [NIST SP 800-56C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf), [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | n/a (KDF) |
| HMAC-SHA-256 | [FIPS 198-1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf) | Post-quantum safe as MAC |
| SHA-256 (for kid) | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | Truncated to 8 bytes |

### Pinned upstream

This package is pinned to:

```
@noble/post-quantum@0.2.1
integrity: sha512-ImgfMp9notXSEocz464o1AefYfFWEkkszKMGO+ZiTn73yIBFeNyEHKQUMS+SheJwSNymldSts6YyVcQDjcnVVg==
```

`@noble/post-quantum` was independently audited by **Cure53** in 2024. Audit report: https://github.com/paulmillr/noble-post-quantum#security

### FIPS posture (be honest)

- ✅ Algorithms implemented are NIST FIPS-standardised (203, 204).
- ❌ This module is **not** FIPS 140-3 CMVP-validated. There is no FIPS module certificate.
- ⚠️ "FIPS-aligned" is the correct way to describe this package; "FIPS-certified" is not.

For deployments where FIPS 140-3 module validation is mandatory, run cryptographic operations inside a validated HSM (AWS CloudHSM, Thales Luna, YubiHSM 2, etc.) and use this library only for envelope construction, kid generation, and verification of incoming signatures.

## Threat model

What this library defends against and what it does not.

### In scope

- ✅ **Quantum adversary against signature non-repudiation** — ML-DSA-65 is the FIPS 204 standard for this.
- ✅ **Quantum adversary against confidentiality of new sessions** — ML-KEM-768 (FIPS 203) for KEM; combine with AES-256-GCM (or equivalent AEAD) for the symmetric envelope.
- ✅ **Forgery of webhook deliveries** — hybrid HMAC + ML-DSA defends against both classical and quantum forgery. ML-DSA adds non-repudiation HMAC cannot give.
- ✅ **Replay attacks** — `webhook.verifyDelivery` enforces a default 5-minute timestamp window.
- ✅ **Tampering with body** — both signatures cover the exact `timestamp + "." + raw_body` envelope.
- ✅ **Wrong-key acceptance** — `pinnedKid` check fails fast before any signature verification.

### Out of scope (caller's responsibility)

- ❌ **Master secret storage**. Keep `KXCO_KEY_MASTER` (or equivalent) in environment variables, a KMS, or an HSM. This library does not store secrets.
- ❌ **Key rotation procedures**. Rotating the master changes every derived keypair; downstream consumers must refresh their pinned kid.
- ❌ **TLS / transport encryption**. Use hybrid `X25519MLKEM768` at the public edge — outside this library's scope.
- ❌ **Receiving raw bodies byte-for-byte**. If you re-stringify JSON before verifying, you will mangle the signature input. Use Express `express.raw({ type: 'application/json' })` or equivalent.
- ❌ **Domain separation hygiene**. If you reuse the same `info` string for signing and encryption keypairs, you create a cross-protocol attack surface. Use distinct `info` per purpose.
- ❌ **Constant-time comparison of secrets outside this library**. We provide `kidEquals` and `verifyHmac`; if you compare HMAC tags yourself with `===`, that's on you.

### Acknowledged limitations

- **Default replay window is 300 seconds**. Configurable via `windowSeconds`. Tighten for high-security paths.
- **`fingerprint` uses 8 bytes (16 hex)**. SHA-256 truncation. Collision-resistant for the scale of keys in use today (one platform key, occasionally rotated). If you anticipate billions of distinct keys, extend to a longer prefix.
- **Side-channel posture**. `@noble/post-quantum` targets constant-time execution; this wrapper adds constant-time string comparisons. Higher-assurance deployments should run operations inside a hardware boundary.
- **`signDelivery` calls `Date.now()`**. If your system clock is wrong, verifiers will reject your deliveries. Run NTP.

## Reproducibility

Test vectors in `test/vectors.json` pin the library's outputs bit-for-bit. Anyone can run `npm test` to verify the library produces identical outputs to the recorded vectors. If a future release changes any output, the run-vectors check fails — this is a deliberate tripwire on cryptographic regressions.

## Disclosure history

None yet. This is a v1 release. Vulnerabilities will be disclosed here as GHSA advisories with CVE numbers where applicable.

## Versioning and support

- We support the latest minor release on the latest major (currently 1.x).
- Critical security fixes are backported to the previous minor for 6 months.
- Major version bumps (2.x → 3.x) only occur when the cryptographic primitives or signed envelope format changes; minor bumps add features without breaking the API.
- `npm install kxco-post-quantum` always pulls the supported version.
