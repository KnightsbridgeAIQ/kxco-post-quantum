# Security Policy

## Reporting

Email `security@kxco.ai` with details. Do not open public issues for security reports.

We acknowledge within 48 hours. Critical findings are triaged within 5 business days.

## Scope

This package wraps `@noble/post-quantum`. Vulnerabilities in the underlying NIST primitives or `@noble/post-quantum` should be reported to that project upstream. This package's scope is the integration patterns: derivation, envelope construction, kid generation, hybrid signing, verification.

## Cryptographic posture

- **Algorithms:** NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65). Both Security Category 3.
- **FIPS module validation:** not held. Algorithms are FIPS-standardised; the module is not CMVP-certified.
- **Side channels:** the underlying `@noble/post-quantum` aims for constant-time execution. This package adds constant-time string compares for kid and HMAC headers. Higher-assurance deployments should run cryptographic operations inside a FIPS 140-3 HSM.
- **Randomness:** all operations use Node's `crypto` module CSPRNG.

## Known limitations

- Public-edge TLS is hybrid X25519MLKEM768, not pure-PQ. This is correct posture for 2026; pure-PQ TLS will be appropriate once the IETF finalises the relevant drafts.
- Replay window default is 5 minutes. Reduce for tighter security.
- Master secret rotation is the caller's responsibility — this library does not manage rotation.

## Audit status

- Underlying primitives (`@noble/post-quantum`) — audited by Cure53 (2024).
- This wrapper — internal review only at present. External audit planned.
