# Algorithm validation: what a lab would be quoting for

Written 18 September 2026, to be sent to NVLAP-accredited CST or 17ACVT
laboratories so their quotes can be compared against the same scope.

Everything below is a measurement or a registration id. Where something is
undecided it says so, because a quote against a guess is not comparable to a
quote against the same guess made differently.

## 1. What is being validated

`kxco-post-quantum`, a JavaScript library implementing the three NIST
post-quantum standards over `@noble/post-quantum` 0.7.0. It is a software module
with no network path: nothing in `src/` opens a socket.

**Scope is CAVP algorithm validation.** A FIPS 140-3 module certificate through
CMVP is a separate and later piece of work, and the published roadmap targets it
for 2027 against a deployment of this library with an HSM rather than against the
library alone. A quote for algorithm validation only is what is wanted here. Say
so if you also quote the module route, but keep the two separately priced.

## 2. Demo certification is already done, and the number to quote

NIST asks for this when Production access is requested:

| | |
|---|---|
| Demo certificate | **A11025** |
| Validation record | `/acvp/v1/validations/42204` |
| Approval requests | 41531, 41532, 41533 |
| Module as registered | `kxco-post-quantum 1.7.2 (Software)` |
| Operational environment | Node.js 26.1.0 on Windows 10 Pro 22H2, Intel Core i7-7700K |

**2,130 cases graded by NIST on 12 and 13 September 2026, zero failures**, per validation record 42204.
Three non-sample sessions. The breakdown below sums to that figure and every
session id is checkable on the validation record above.

| Session | Vector sets | Cases |
|---|---|---|
| 767289 | ML-KEM keyGen and encapDecap, ML-DSA keyGen, sigGen and sigVer | 882 |
| 767291 | SLH-DSA keyGen and sigVer | 624 |
| 767292 | SLH-DSA sigGen | 624 |

This is a **Demo** certificate. It is not a CAVP validation, it does not appear
on the public algorithm validation list, and it is not a certification of the
firm. It is stated here because it is the prerequisite for a Production request
and because it tells you the responder already speaks the protocol correctly.

Registered and reusable on the demo database: vendor 14548 Knightsbridge
Financial Ltd, person 16779, operational environment 34701, module 15488.

## 3. Algorithms and parameter sets in scope

| Standard | Algorithm | Parameter sets |
|---|---|---|
| FIPS 203 | ML-KEM | ML-KEM-768, ML-KEM-1024 |
| FIPS 204 | ML-DSA | ML-DSA-65, ML-DSA-87 |
| FIPS 205 | SLH-DSA | ten parameter sets, with published helpers for SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192s and SLH-DSA-SHAKE-256f |

## 4. READ THIS BEFORE QUOTING: the claim is narrower than NIST's matrix

This is the one thing that changes a quote, and it is stated up front rather than
discovered during testing.

**The backend refuses any pre-hash whose collision strength falls below the
parameter set's security category.** For example SHA2-256 with ML-DSA-87, which
offers 128 bits against 256 required, and SHAKE-128 with ML-DSA-65, 128 against
192.

NIST's vector files pair every approved hash with every parameter set, including
those combinations. The library rejects them rather than signing. **135 of 975
pinned cases are declined on that rule.**

Two facts about it, both load bearing:

- It is the library being **stricter** than the vector file, not weaker. A
  declined case is a refusal to sign, not a wrong answer.
- It is `@noble/post-quantum`'s policy, **not a FIPS 204 or 205 requirement**. So
  it is a deviation from the reference matrix that a lab has to either accept as
  documented, or require us to change.

Skips are counted separately from passes in every report we publish, because a
skip is not a pass. The ACVTS registration derives the pre-hash list per
parameter set from the same rule.

**Please say in your quote which of the two you would do**: validate the narrower
matrix as it stands, or require the backend to accept the weaker pairings first.
The second is an engineering change on our side and we would want to know before
starting rather than after.

## 5. Two open questions we are asking you to price, not answer

**Which implementation.** The evidence above is for the JavaScript path only. An
OpenSSL 3.5 backend also exists and has never been run against ACVTS. We have not
decided which implementation carries the certificate. If your pricing differs
between them, quote both.

**Version binding.** The demo certificate names 1.7.2. The current published
release is 1.7.3, which changed packaging metadata and added no algorithm, key
format or wire format change. Tell us whether you would validate against 1.7.2 as
certified, or re-run against the current release, and what that costs.

## 6. What we can hand you on day one

- The full ACVTS client, in `conformance/acvts/`, with a README carrying every
  protocol trap we hit
- `selftest.mjs`, which proves the responder against pinned vectors offline: 840
  matched, 0 mismatched, before anything is sent to a live NIST system
- Per-case results with every skip listed and its reason, written by CI to
  `conformance/results/`
- A CycloneDX SBOM, generated by `npm sbom` from the published tree
- Reproducible test vectors in `test/vectors.json` covering every primitive

## 7. What we need back

1. A price and elapsed time for CAVP algorithm validation at the scope in
   section 3, against the deviation in section 4.
2. Separately priced, if you offer it: FIPS 140-3 module validation of a
   deployment of this library with an HSM.
3. Whether you hold 17ACVT accreditation, CST, or both.
4. What you need from us that is not in section 6.

Contact and commercial terms follow separately. This document is scope only.
