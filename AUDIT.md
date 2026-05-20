# Audit Posture

**Status as of v1.0.1 release (2026-05-21).** Self-attested. No third-party audit of this wrapper library has been performed yet. This document exists to make our posture **legible to reviewers** so the right questions get asked of the right party.

If you are doing institutional due diligence, read this end-to-end before the README.

---

## 1. What has been audited (upstream)

**`@noble/post-quantum@0.2.1`** — the underlying NIST primitives we wrap — has been independently audited.

| Auditor | Year | Scope | Report |
|---|---|---|---|
| **Cure53** | 2024 | `@noble/post-quantum` cryptographic primitives | https://github.com/paulmillr/noble-post-quantum#security |

This audit covers the actual cryptographic operations: ML-DSA-65 sign/verify, ML-KEM-768 keygen/encapsulate/decapsulate, the constant-time properties, the test vector compliance with NIST's reference outputs.

When you `npm install kxco-post-quantum`, the audited code is what runs the math. This wrapper does not reimplement the primitives.

The exact upstream we pin:

```
@noble/post-quantum@0.2.1
integrity: sha512-ImgfMp9notXSEocz464o1AefYfFWEkkszKMGO+ZiTn73yIBFeNyEHKQUMS+SheJwSNymldSts6YyVcQDjcnVVg==
```

## 2. What has NOT been audited (this wrapper)

The integration patterns in this package — `pqSigner` derivation, kid fingerprinting, webhook envelope construction, hybrid HMAC + ML-DSA signing, timestamp replay enforcement — have not been independently audited.

What we have done:

- **Internal review** by the KXCO engineering team and KXCO Cybersecurity (lead: Sean O'Coiligh, 30+ years cybersecurity, formerly led Offensive Cyber at the DTCC Cyber Threat Fusion Center)
- **Reproducible test vectors** in `test/vectors.json` covering every primitive — anyone running `npm test` gets the same outputs the maintainers see
- **Production deployment** across the KXCO platform (KnightsVault, KXCO Bank, KnightsBot, The Exchequer, Armature L1) since November 2025
- **Public verifiable proof** of the signing identity at https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey — anyone can fetch the kid, install this library, and verify signatures from the production fleet

What we have **not** done:

- ❌ Engaged a third-party auditor for this wrapper
- ❌ Held a public security review window with bug bounty
- ❌ Obtained CMVP FIPS 140-3 module certification
- ❌ Submitted to ENISA / NCSC / BSI evaluation schemes

## 3. Audit roadmap

| Milestone | Target | Owner |
|---|---|---|
| Engage external auditor for wrapper integration patterns | Q3 2026 | KXCO Engineering |
| Public bug bounty programme | Q4 2026 | KXCO Security |
| Apply for FIPS 140-3 CMVP validation of a cryptographic module deployment using this library + an HSM | 2027 | KXCO Compliance |
| NIST PQC Workshop presentation (production lessons) | When workshop opens for 2026/27 | Shayne Heffernan + Sean O'Coiligh |

The exact dates depend on engineering and budget capacity. The order is committed.

## 4. Reproducibility checks (run these yourself)

You do not have to trust us. Run these to verify:

```bash
# Clone and install
git clone https://github.com/<destination-tbd>/kxco-post-quantum   # repo URL on npm page
npm install

# Run the full test suite — primitives + vectors
npm test

# Run vector verification only
npm run test:vectors

# Fetch the live production platform key and verify offline
curl https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey
```

Expected: `npm test` reports `✓ All 29 checks pass — library output matches pinned vectors bit-for-bit.`

## 5. Threat model summary

See [SECURITY.md](./SECURITY.md) for the full threat model. In short:

- **In scope:** quantum signature non-repudiation, quantum-safe KEM, webhook forgery resistance, replay rejection, body tamper detection, wrong-key rejection.
- **Out of scope:** master secret storage (use KMS/HSM), TLS termination (use OpenSSL 3.5+), receiving raw bodies byte-for-byte (use `express.raw` or equivalent), key rotation procedures (caller's responsibility).

## 6. Bug-finding signals

If you are evaluating this library, look at:

- **Test coverage:** 9 functional tests + 29 vector checks = 38 distinct assertions covering every export
- **Code size:** ~280 source lines across 6 modules — small enough to review end-to-end in an afternoon
- **Dependency surface:** one runtime dependency (`@noble/post-quantum`), itself audited
- **Determinism:** every output is reproducible from inputs — no hidden state, no globals beyond a lazy cache, no network
- **API stability:** v1.0 commits to the public surface listed in CHANGELOG.md

## 7. Reviewer checklist

For institutional reviewers, the smallest version of "did they actually do the work":

- [ ] `npm view kxco-post-quantum dist.signatures` returns a signed package
- [ ] `npm test` passes after fresh clone + install
- [ ] `npm run test:vectors` matches the pinned vectors
- [ ] `curl https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey` returns a valid ML-DSA-65 public key
- [ ] The kid (`kid` field above) matches `fingerprint()` of the returned `publicKey` field
- [ ] An outbound webhook from `chain.kxco.ai` verifies with `webhook.verifyDelivery` against the pinned kid

All six are reproducible without any cooperation from KXCO. That's the standard we hold ourselves to.

---

**Contact:** security@kxco.ai for vulnerability reports. audit@kxco.ai for due-diligence and review requests.
