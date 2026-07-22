# Security Policy

## Reporting a vulnerability
Email **security@kxco.ai**. Do not open public issues for security reports.
PGP key available on request. We respond within 48 hours and credit reporters
in `CHANGELOG.md` unless they request otherwise.

## Scope
In scope:
- Cryptographic correctness of the wrappers in this package
- Constant-time guarantees on signature/HMAC comparison
- Replay-window enforcement in `webhook.verify`
- HKDF domain separation in `derive`
- Kid fingerprint collision behaviour

Out of scope (report upstream to https://github.com/paulmillr/noble-post-quantum):
- Bugs in the underlying ML-DSA-65, ML-KEM-768, SLH-DSA-SHA2-192s, or HKDF primitives

## Algorithms used
- ML-DSA-65 — NIST FIPS 204 (lattice signatures)
- ML-KEM-768 — NIST FIPS 203 (key encapsulation)
- SLH-DSA-SHA2-192s — NIST FIPS 205 (hash-based signatures)
- HMAC-SHA-256
- HKDF-SHA-512 (RFC 5869)

## Disclosure
We follow coordinated disclosure with a 90-day default window.
For actively-exploited issues we ship a patch release within 48 hours.
