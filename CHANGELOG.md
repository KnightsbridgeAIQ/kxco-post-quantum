# Changelog

All notable changes to `kxco-post-quantum` are documented here. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-21

First stable release. The public API is committed to: future minor/patch releases will not break it without a major version bump.

### Included
- **`mlDsa`** — ML-DSA-65 (NIST FIPS 204, Dilithium3) sign + verify with deterministic `keypairFromMaster`
- **`mlKem`** — ML-KEM-768 (NIST FIPS 203, Kyber768) encapsulate + decapsulate with deterministic `keypairFromMaster`
- **`deriveSeed`** — HKDF-SHA-512 derivation with domain separation
- **`fingerprint` / `kidEquals`** — 16-hex public-key kid + constant-time compare
- **`webhook`** — hybrid HMAC-SHA-256 + ML-DSA-65 signing helpers (`signDelivery`, `verifyDelivery`, `envelope`, `hmacHex`, `verifyHmac`, `pqSign`, `verifyPq`)

### Verified
- Production-tested at KXCO across KnightsVault, KXCO Bank, KnightsBot, The Exchequer, and Armature L1
- 9/9 round-trip tests passing — sign+verify, encapsulate+decapsulate, hybrid delivery, replay rejection, tamper rejection
- Underlying primitives via `@noble/post-quantum@^0.2.1` (audited by Cure53, 2024)

### Notes
- ESM-only. Node.js 18+.
- FIPS-aligned (implements FIPS 203/204 algorithms). Not CMVP-validated as a module.
- TLS guidance: use OpenSSL 3.5+ for `X25519MLKEM768` hybrid at the edge — this package does not handle TLS.

## [0.1.0] — 2026-05-21

Initial pre-release. Same surface as 1.0.0; promoted after 0.1.0 verified clean install and round-trip on a fresh environment.
