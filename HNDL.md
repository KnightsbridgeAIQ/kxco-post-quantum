# HNDL exposure register

Harvest-now-decrypt-later exposure for `kxco-post-quantum` 1.7.2, as required
at Level 3 of the PKI Consortium PQCMM: which data flows handled by the product
carry a long-lived confidentiality requirement, and which algorithm protects
each.

## What HNDL is, and why most of this register is short

HNDL is a confidentiality attack. An adversary records ciphertext today and
decrypts it once a cryptographically relevant quantum computer exists. It
applies to data whose confidentiality must outlast that machine.

It does **not** apply to signatures in the same way. A signature forged in 2040
is worthless against a document verified in 2026, because the verification
already happened. The quantum risk to a signature scheme is forgery of *future*
verifications, which is an integrity and non-repudiation problem with a
different shape and a different deadline. Registers that fold the two together
overstate their own exposure, and this one keeps them apart.

**This package is predominantly a signing library.** Most of what it handles is
therefore outside HNDL by nature, and the register is short for a real reason
rather than an incomplete one. Where confidentiality genuinely is at stake, the
rows below say so.

## Register

| # | Data flow | Long-lived confidentiality? | Protected by | Quantum-safe | Residual |
|---|---|---|---|---|---|
| 1 | Private keys and seeds held in caller memory | **Yes, for the key's whole life** | Nothing in this package. Caller's process isolation | Not a cryptographic control | **The primary exposure.** See below |
| 2 | Master secret used by `keypairFromMaster` | **Yes, and it is worse than a single key** | Nothing in this package. Caller's storage | Not a cryptographic control | Compromise derives every child key, past and future |
| 3 | ML-KEM shared secret, in transit | Depends entirely on the caller's use | ML-KEM-768 or ML-KEM-1024 (FIPS 203) | **Yes** | The classical half of a hybrid pairing, if the caller adds one |
| 4 | Payload a caller encrypts under an ML-KEM-derived key | Caller's to determine | The caller's AEAD, not ours | Symmetric, so Grover only | Key size is the caller's choice; this package does not perform the encryption |
| 5 | Package delivery over TLS to npm or GitHub | **No** | Classical TLS | No | Confidentiality is irrelevant: the package is public. Integrity is the concern and ML-DSA-65 covers it |
| 6 | Signatures, JWS, webhook envelopes | **No** | ML-DSA-65 or SLH-DSA, plus HMAC-SHA-256 on webhooks | Yes | Integrity risk, not HNDL. Recorded here only so its absence is deliberate |
| 7 | Evidence bundle and SBOM | **No** | Published deliberately | Not applicable | Public by design |
| 8 | Keys held on a PKCS#11 token via `kxco-pq-hsm` | Yes, but outside this boundary | `CKA_EXTRACTABLE=false` | Hardware control | The vendor's channel to the token is the vendor's, per `BOUNDARY.md` |

## The two rows that matter

**Rows 1 and 2 are the real HNDL exposure of this product, and neither is
solved by a post-quantum algorithm.**

A private key is confidential for its entire life, which is exactly the
long-lived requirement HNDL describes. An adversary who harvests a stored
ML-DSA private key today does not need a quantum computer at all; they need the
key. The algorithm being post-quantum protects the signature against
cryptanalysis, not the key against theft. So the strongest post-quantum
posture in this package does nothing for its largest confidentiality asset.

Row 2 is worse in one specific way. A master secret under HKDF-SHA-512
regenerates every derived keypair, for every `info` string, past and future. It
is a single point whose compromise is not bounded in time. That is the correct
tradeoff for reproducible keys and pinnable conformance vectors, and it is the
right design, but the concentration of risk should be visible rather than
implied.

Neither row has a cryptographic mitigation available inside a library. What
exists is the escape in row 8: `kxco-pq-hsm` generates keys on a PKCS#11 token
with `CKA_EXTRACTABLE=false`, after which this package handles verification
only and touches no secret. **A deployment with a long-lived confidentiality
requirement on its keys should be using that path, and this register exists in
part to say so.**

## What this register does not cover

Callers. This package has no visibility into what a caller encrypts, how long
they need it confidential, or where they put a key. Rows 3 and 4 are marked as
the caller's to determine because they genuinely are, and a register claiming
otherwise would be inventing knowledge it does not have.

The absence of long-term validation, recorded as category 10 of
`CRYPTO-INVENTORY.md`, is an adjacent gap rather than an HNDL one. No
timestamps, no validity windows, no revocation. It bears on whether an old
signature can still be trusted, not on whether old ciphertext can be read.

## Review

This register is a claim about a shipped version and it ages. It should be
re-read whenever a new cryptographic use case enters the package, whenever a
category in `CRYPTO-INVENTORY.md` changes status, and on any change to how
seeds or master secrets are handled.

Last reviewed against 1.7.2 on 2026-09-09.
