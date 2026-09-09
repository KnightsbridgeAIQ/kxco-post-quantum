# Cryptographic inventory

Every use case in this package where cryptography is applied, mapped onto the
ten categories of the PKI Consortium PQCMM cryptographic inventory taxonomy.

The model requires that no category is omitted. A category that does not apply
is marked not applicable with a written reason, because "we do not do that" and
"we did not look" are indistinguishable from the outside unless the reason is
recorded. Four of the ten genuinely do not apply to a library with no sockets
and no persistent state, and saying so in one line each is the honest answer
rather than a padded one.

Scope: `kxco-post-quantum` 1.7.2. `BOUNDARY.md` is the companion document and
explains the difference between cryptography this package performs, depends on,
and merely offers to a caller. The distinction matters here: a caller can use
this package inside a category that the package itself does not implement.

## 1. Data in transit

**Not applicable to the library. Applicable to its delivery.**

Nothing in `src/` opens a socket. The library performs no network operation at
any point: no licence check, no telemetry, no key server, no call home. There
is no transport for it to protect.

Its own delivery is a different matter and is not quantum-safe. Fetching the
package is classical TLS to the npm registry or to GitHub, as was the transport
that delivered any git clone. That residual is stated in `BOUNDARY.md` and is
mitigated by an ML-DSA-65 signature over every release asset plus a second copy
of the public key committed to the repository, so that a verifier is not
trusting the same channel twice. Mitigated, not eliminated.

What the package offers a caller for this category is the ML-KEM key
encapsulation below, from which a caller may build a transport. Offering a
primitive is not the same as protecting a transport, and the two should not be
reported as one.

| Use | Algorithm | Quantum-safe |
|---|---|---|
| Package delivery | TLS to registry and GitHub, classical | No, mitigated by signature |
| Primitive offered to callers | ML-KEM-768, ML-KEM-1024 | Yes |

## 2. Data at rest

**Not applicable.** The package writes no files and keeps no state between
calls. There is no disk, database or object storage in its boundary to encrypt.

A caller who persists a key or a seed produced by this package is performing
data-at-rest protection in their own system, with their own choice of
algorithm, and this package neither sees nor constrains it. The one supported
route that removes the question is `kxco-pq-hsm`, which generates ML-DSA keys
on a PKCS#11 token with `CKA_EXTRACTABLE=false`, after which this package
handles verification only and touches no secret.

## 3. Identity, authentication and certificates

**Applicable, and quantum-safe within the package.**

No X.509. No certificate chain, no path validation, no revocation. Identity
here is a raw key plus a key identifier, and the package deliberately does not
pretend to be a PKI.

| Use | Algorithm | Quantum-safe |
|---|---|---|
| Signature and verification | ML-DSA-65, ML-DSA-87 (FIPS 204) | Yes |
| Hash-based alternative | SLH-DSA, ten parameter sets (FIPS 205) | Yes |
| Key identifier | SHA-256 over the public key, truncated to 16 hex characters (`kid.js`) | Yes, second-preimage bound |
| Key interchange | JWK `kty: AKP` per RFC 9964, and PKCS#8 seed export | Format, not an algorithm |
| JWS signing | ML-DSA over the JWS signing input (`jws.js`) | Yes |
| Webhook delivery signing | HMAC-SHA-256 **and** ML-DSA-65, both (`webhook.js`) | Yes, hybrid |

The `kid` is a truncated SHA-256, so it is a 64-bit identifier and not a
security boundary. It identifies which key to try; it does not authenticate
anything. Grover halves the preimage work on SHA-256 and the truncation
dominates that anyway, which is why nothing in the package makes a trust
decision on a `kid` alone.

## 4. Code, firmware and update signing

**Applicable, and quantum-safe.**

Every release asset is signed with ML-DSA-65 by this package's own signing
path, which means the signing of the package is performed by the thing being
signed. The public key is committed to the repository at
`release-signing-key.pub.hex` and published as a release asset, so a verifier
can obtain it by a path other than the one that delivered the artefact.
Verification is four lines and is in `README.md`.

No firmware. The package ships no binary and no native build of its own; the
native path calls the OpenSSL already present in the host runtime.

| Use | Algorithm | Quantum-safe |
|---|---|---|
| Release asset signing | ML-DSA-65 | Yes |
| Signature over the evidence bundle | ML-DSA-65, `.sig` beside each bundle | Yes |

## 5. Key wrapping and key-encryption keys

**Applicable in a limited form, and quantum-safe.**

The package wraps no keys. It has no KEK hierarchy, no envelope encryption and
no key store.

What it does have is deterministic derivation, which occupies the same place in
a design without being key wrapping. `keypairFromMaster` derives a per-purpose
seed from a caller-held master secret using HKDF-SHA-512 with an empty salt and
a caller-chosen `info` string, then generates the keypair from that seed. A
master secret therefore stands in the position a KEK would occupy, and its
protection is entirely the caller's.

| Use | Algorithm | Quantum-safe |
|---|---|---|
| Seed derivation from a master secret | HKDF-SHA-512 (`derive.js`) | Yes, symmetric |
| Key encapsulation offered to callers | ML-KEM-768, ML-KEM-1024 (FIPS 203) | Yes |
| Hybrid key establishment | `deriveSeed` combines an ML-KEM shared secret with a classical secret through the KDF | Yes, holds if either half holds |

## 6. Random number generation and entropy sources

**Applicable, and this is the entry a reader should not skim.**

**This package generates no randomness in its JavaScript backend.** There is no
`randomBytes`, no `getRandomValues`, no `randomFillSync` anywhere in `src/`
outside the native path. Every keypair is produced from a seed the caller
supplies, either directly through `keypairFromSeed` or derived from a
caller-held master through `keypairFromMaster`. Seed length is enforced against
the FIPS parameter set and a wrong length is a `RangeError`, not a silent pad.

The consequence is worth stating plainly: **in the JavaScript backend, the
quality of every private key in this system is a property of the caller's
entropy source, not of this package.** A caller who supplies a low-entropy seed
gets a low-entropy key and the library cannot detect it. This is a deliberate
design choice, because deterministic derivation is what makes the keys
reproducible and the conformance vectors pinnable, but it relocates a security
property rather than solving it.

The native backend is different. `crypto.generateKeyPairSync` in `_native.node.js`
delegates to Node and thence to the OpenSSL DRBG, so on that path entropy comes
from the operating system.

| Path | Entropy source | Whose responsibility |
|---|---|---|
| JavaScript backend | Caller-supplied seed | The caller |
| JavaScript backend, derived | HKDF-SHA-512 over a caller-supplied master | The caller |
| Native backend keygen | OpenSSL DRBG via `crypto.generateKeyPairSync` | The operating system |

No category of quantum attack applies to a DRBG in the way it applies to a
public-key primitive; the risk here is classical and it is entropy starvation.

## 7. Telemetry, logging and audit-trail integrity

**Not applicable.** The package emits no telemetry and writes no log. It keeps
no state between calls, so there is no audit trail of its own to protect.

Log integrity in the wider KXCO estate is `kxco-pq-audit`, a separate package:
SHA-256 hash-chained entries, each signed with ML-DSA-65, with periodic seals
anchored on Armature L1 so that a verifier who does not trust the log operator
still has an independent time bound. What this package contributes to that is
the signature primitive and nothing else.

## 8. Build, CI/CD and supply-chain signing

**Applicable, and quantum-safe for what we sign, classical for what GitHub and
npm sign.** This split is the honest answer and collapsing it would be an
overclaim.

| Use | Algorithm | Quantum-safe |
|---|---|---|
| Release assets and evidence bundle | ML-DSA-65, ours | Yes |
| SLSA provenance attestation | Sigstore, classical (ECDSA and the Fulcio and Rekor chain) | **No** |
| npm registry signature and provenance | npm's own, classical | **No** |
| Reproducible build | Not a signature. The published tarball rebuilds bit-for-bit from its own tag, verified in CI on every run | Not applicable |
| CycloneDX SBOM | Generated by `npm sbom` from the published tree; integrity carried by the ML-DSA signature over the release | Yes, via the release signature |

The reproducible build is the part of this category that does not depend on any
signature algorithm at all, and it is the reason the classical rows above are a
weaker residual than they look: a verifier who rebuilds from source is not
trusting Sigstore, npm or us.

## 9. Attestation and remote attestation

**Applicable in the supply-chain sense only.**

There is no hardware attestation, no TPM quote, no confidential-computing
report and no remote-attestation protocol in this package.

What exists is build attestation: an in-toto statement at
`evidence.intoto.jsonl` and an evidence manifest that pins the commit, the
toolchain, the backend, the dependency versions and every step with its exact
command, result and duration, with a SHA-256 for each file in the bundle. The
in-toto and SLSA layer is signed classically by Sigstore, as row 2 of category
8 records. The manifest and bundle are additionally signed with ML-DSA-65 by us.

## 10. Backup, archival and long-term storage

**Applicable as a stated gap, and this is the weakest category.**

Verification of old records holds: a signature made by any version of this
package verifies under any later version. Wire formats have not changed, and
the conformance evidence is regenerated against pinned vectors on every
dependency bump, which is the control that would catch a change breaking them.

Long-term trust does not hold and is a different question. This package has no
notion of key validity windows, no revocation and no trusted timestamps. It can
tell you a signature is arithmetically valid. It cannot tell you the key was
still trusted when the signature was made. Anything that has to hold for years
needs a time anchor outside the signature. Inside the KXCO estate that anchor
is `kxco-pq-audit`'s on-chain seals. Outside it, this is a gap the deployment
has to close, and this package should not be cited as closing it.

## Summary

| # | Category | Status |
|---|---|---|
| 1 | Data in transit | Library N/A; delivery is classical TLS, signature-mitigated |
| 2 | Data at rest | N/A, no persistence |
| 3 | Identity, authentication, certificates | Quantum-safe, no X.509 |
| 4 | Code, firmware, update signing | Quantum-safe |
| 5 | Key wrapping and KEKs | Quantum-safe, no wrapping; master secret is the caller's |
| 6 | RNG and entropy | **Relocated to the caller** in the JavaScript backend |
| 7 | Telemetry, logging, audit integrity | N/A, separate package |
| 8 | Build, CI/CD, supply chain | Split: ours quantum-safe, Sigstore and npm classical |
| 9 | Attestation | Build attestation only, classically signed at the Sigstore layer |
| 10 | Backup, archival, long-term | **Gap.** No timestamps, validity windows or revocation |

Three residuals carry forward into `PQCMM.md` and `HNDL.md` rather than being
recorded only here: classical release transport, the classical Sigstore and npm
signature layer, and the absence of long-term validation.
