# PQC Maturity Model self-assessment

PKI Consortium PQC Maturity Model (PQCMM), assessed against the model as
published at <https://pkic.org/wg/pqc/pqcmm/>.

**Declared level: 3 (Advanced).**

A self-assessment is indicative, not authoritative. It is the vendor's own view
and it has not been independently verified. The model says relying parties
should treat a self-assessed level as a signal rather than a guarantee, and that
is how this document should be read. Where a criterion is not met, this document
says so and names what is missing rather than reporting a partial as a pass.

## Scope

| Field | Value |
|---|---|
| Product | `kxco-post-quantum` |
| Version assessed | 1.7.2 |
| Commit | `90b5778b4d19ed0f78715e143a6a50b9170b70f9`, clean tree |
| Registry | <https://www.npmjs.com/package/kxco-post-quantum> |
| Licence | Apache-2.0 |
| Assurance method | Self-assessment |
| Date | 2026-09-09 |

A PQCMM assessment applies to a single product. The other `kxco-pq-*` packages
depend on this one and are not covered here; each needs its own assessment.

## Evidence available to an assessor

Everything cited below is a permanent unauthenticated URL. No account, no
request to us, no expiring artifact.

| Artefact | Path under the release |
|---|---|
| Evidence manifest | `releases/latest/download/manifest-node24.x.json` |
| Evidence bundle | `releases/latest/download/evidence-node24.x.zip` |
| CycloneDX SBOM | `releases/latest/download/sbom.cyclonedx.json` |
| In-toto attestation | `releases/latest/download/evidence.intoto.jsonl` |
| Release signing key | `releases/latest/download/release-signing-key.pub.hex` |

Base: `https://github.com/KnightsbridgeAIQ/kxco-post-quantum/`

Two documents in the repository carry the Level 3 evidence and are cited
throughout: `CRYPTO-INVENTORY.md` for the ten-category cryptographic inventory,
and `HNDL.md` for the harvest-now-decrypt-later exposure register.

The manifest pins the commit, the toolchain (Node 24.20.0, OpenSSL 3.5.7), the
backend, the dependency versions, and every step with its exact command, its
result and its duration. Each file in the bundle carries its SHA-256. The
conformance and interop runs are reproducible from the commands recorded in the
manifest rather than taken on our word.

## Level 1, Initial: MET

| # | Criterion | Answer | Evidence |
|---|---|---|---|
| 1 | A quantum-safe algorithm in a released build | Yes | ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203), SLH-DSA-SHA2-192s (FIPS 205) in 1.7.2 on the public npm stable channel. Category 5 sets ML-DSA-87 and ML-KEM-1024 also ship. |
| 2 | The feature can be enabled | Yes | Available on import. No flag, no custom build, no source modification. |
| 3 | Documented for evaluation | Yes | `README.md`, with a per-function API reference. |

Release channel is stable and public, available to all consumers, with no
programme enrolment. Ten SLH-DSA parameter sets are exposed, not one.

## Level 2, Foundational: MET

| # | Criterion | Answer | Evidence |
|---|---|---|---|
| 1 | Quantum-safe algorithms in core production functionality | Yes | Signing, key encapsulation, key derivation and fingerprinting are the product's core, not a preview channel. |
| 2 | Compatibility with a published standard from a recognised body | Yes | NIST FIPS 203, 204 and 205. |
| 3a | Standards-conformance testing | Yes | 2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped. Every skip is this library refusing a pre-hash weaker than the parameter set, listed individually with its reason. A skip is not counted as a pass. See `CONFORMANCE.md` and manifest steps `acvp`, `acvp-fips205`, `acvp-fips205-siggen`. |
| 3b | Interoperability against an independent conformant implementation | Yes, four of them | 225 cross-implementation checks, 0 failed, both directions, with negative controls, against liboqs, Bouncy Castle and two pure-Python implementations. Run against both backends. Manifest step `interop`. |
| 3c | Functional security testing as configured for production | Yes | `npm test` recorded in the manifest, plus the fuzz corpus under `fuzz/`. |
| 3d | Smoke performance test under representative load | Yes | `BENCHMARKS.md`: per-algorithm p95 and p99 on both backends, on x86-64 and arm64, plus memory. |
| 4 | Documented for production use including known limitations | Yes | `THREAT-MODEL.md` for what is and is not defended, `BOUNDARY.md` for which cryptography this package performs versus depends on versus offers, plus `LIFECYCLE.md` and `MIGRATION.md`. |

Level 2 asks for CAVP or ACVTS results "or equivalent". Ours are the NIST ACVP
vectors run by us and published with the commands to reproduce them. That is
equivalent evidence, not a NIST certificate. **There is no CAVP certificate
number for this product.** An assessor checking the CAVP or CMVP database will
find nothing, and should record that.

## Level 3, Advanced: MET

| # | Criterion | Answer | Evidence |
|---|---|---|---|
| 1 | Full cryptographic inventory across every applicable taxonomy category | Yes | `CRYPTO-INVENTORY.md` covers all ten categories. Four are marked not applicable with a written reason; none is omitted. |
| 2 | Non-quantum-safe features documented and flagged | Yes | `BOUNDARY.md`, "The gaps, collected", and the classical rows of `CRYPTO-INVENTORY.md` categories 1, 8 and 9. |
| 3 | SBOM or equivalent component inventory | Yes | CycloneDX SBOM as a release asset at a permanent URL, generated by `npm sbom` from the tree that was published. Manifest step `sbom`. |
| 4 | Crypto agility, two algorithms selectable in the same role | Yes | ML-DSA-65 and SLH-DSA-SHA2-192s are both available in the signature role by configuration, which is two different algorithms rather than two parameter sets of one. `AGILITY.md` separates the replacement plan, the implemented mechanism and the interoperable transition, and states what the package does not give you. |
| 5 | Documented HNDL exposure register | Yes | `HNDL.md`. Eight data flows, each with its confidentiality horizon, its protecting algorithm and its residual. |

Writing the inventory against the taxonomy produced two findings that this
package's own audit documents had not stated, and both are recorded rather than
smoothed over.

**The library generates no randomness in its JavaScript backend.** Every
keypair comes from a caller-supplied seed, or from a master secret through
HKDF-SHA-512. So in that backend the entropy quality of every private key is a
property of the caller, not of this package, and the package cannot detect a
weak seed. The native backend differs: `crypto.generateKeyPairSync` uses the
OpenSSL DRBG. `CRYPTO-INVENTORY.md` category 6.

**The largest HNDL exposure in this product has no post-quantum mitigation.**
Private keys and, more sharply, the master secret behind `keypairFromMaster`
are confidential for their whole life, which is precisely the long-lived
requirement HNDL describes. A post-quantum algorithm protects the signature
against cryptanalysis and does nothing for the key against theft. The available
answer is the PKCS#11 path in `kxco-pq-hsm`, not an algorithm choice here.
`HNDL.md`, rows 1 and 2.

## Level 4, Managed: NOT MET

| # | Criterion | Answer | Evidence or gap |
|---|---|---|---|
| 1 | CBOM maintained | **No** | The product publishes an SBOM, not a CBOM. `CRYPTO-INVENTORY.md` now records each algorithm with its protocol context and usage purpose, which is the human-readable half of what a CBOM carries, but it is prose rather than a machine-readable CBOM and key sizes are stated by parameter set rather than per field. Closing this means emitting a CycloneDX CBOM as a release asset, which is a build change rather than a document. |
| 2 | Zero-legacy capability across every in-scope component | **Not determined** | Not assessed against the model's wording, which extends to boot, firmware update signing, hardware-bound operations and internal diagnostics. Claiming it without that determination would be an overclaim. |
| 3 | Symmetric and hash strengths adequate beyond CRQC availability | Yes | SHA-256 for key identifiers and webhook HMAC, SHA-512 under HKDF for seed derivation, via `@noble/hashes` 2.4.0. Per-use detail in `CRYPTO-INVENTORY.md`. |
| 4 | Hybrid and composite support documented, with contexts | Partial | Hybrid is documented: `webhook` performs HMAC plus ML-DSA-65 delivery signing, and `deriveSeed` exists to combine an ML-KEM shared secret with a classical secret through a KDF. Composite, in the algorithm-fused sense, is not supported and is not currently stated as unsupported. |

## Level 5, Optimized: NOT MET

| # | Criterion | Answer | Evidence or gap |
|---|---|---|---|
| 1 | Quantum-safe by default, legacy requires explicit enablement | Yes | There is no classical algorithm to fall back to. The default parameter set is Category 3. |
| 2 | Benchmarked and tuned against operational requirements | Yes | `BENCHMARKS.md`. Two figures stated rather than hidden: ML-DSA signing keeps a rejection-sampling tail on either backend, and SLH-DSA-SHA2-192s signs in seconds rather than milliseconds. |
| 3 | Primarily follows standards from a recognised body | Yes | FIPS 203, 204 and 205. |
| 4 | **Independently verified or certified** | **No** | No FIPS 140 validation. No Common Criteria evaluation. The underlying `@noble/post-quantum` 0.7.0 has no published third-party formal security analysis covering the implemented PQC algorithms, so the library-based route in the model's wording is not available either. |

Criterion 4 is the binding constraint and it cannot be closed by documentation.
It requires a paid engagement: a CAVP or CMVP validation through an accredited
laboratory, a Common Criteria evaluation, or a published independent audit of
the cryptographic implementation.

## Assessment methodology record

The model requires this record to accompany an assessment.

- **Evidence method.** Documentation review, plus the published evidence
  manifest, plus verification of the licence state of every published package
  against the public npm registry on 2026-09-09.
- **Cryptographic library.** `@noble/post-quantum` 0.7.0 and `@noble/hashes`
  2.4.0 in the JavaScript backend; `node:crypto` on OpenSSL 3.5.7 in the native
  backend. Both versions are recorded in the manifest. `@noble/post-quantum` is
  maintained, and its PQC support is confirmed from its public repository. It
  has **not** been independently audited. Version 0.7.1 is deliberately not
  adopted because it regressed SLH-DSA, so the dependency is pinned at 0.7.0.
- **Reproduction attempts.** All conformance, interop, test and SBOM steps in
  the manifest ran in CI from a clean tree at commit `90b5778`, on Node
  24.20.0, linux-x64, on 2026-09-08. Every step reports `ok: true`, and
  `sampling.full` is `true`.
- **Public database checks.** npm registry, all sixteen published `kxco-*`
  packages, 2026-09-09: every one reports `Apache-2.0`. NIST CAVP and CMVP: no
  certificate exists for this product, confirmed rather than assumed.
- **Unverified claims.** Every criterion answered Yes above is vendor-stated and
  not independently verified. That is what a self-assessment is. The manifest
  and the bundle exist so that an assessor can convert these into verified
  findings without asking us for anything.

## Corrections

If any statement here is wrong, it should be corrected here first, and the
correction dated. Facts about this package that are commonly recorded wrongly,
with the one-line check for each, are listed at the top of `README.md`.
