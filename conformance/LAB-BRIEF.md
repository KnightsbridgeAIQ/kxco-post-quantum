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
| FIPS 205 | SLH-DSA | all 12 parameter sets, with published helpers for SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192s and SLH-DSA-SHAKE-256f |

The 12 are what the ACVTS registration in `conformance/acvts/registrations.mjs`
claims and what NIST graded. Section 5 narrows this: the implementation we are
asking you to certify covers 3 of the 12, not all of them.

## 4. READ THIS BEFORE QUOTING: the claim is narrower than NIST's matrix

**This section describes the JavaScript implementation.** Section 5 asks you to
certify the other one, where the constraint is different and wider. Read both
before pricing.

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

## 5. Which implementation we want certified, and what that costs

**The decision is the native path.** Two implementations ship inside one
package. It picks between them at import time by probing the runtime, not by
reading a version number. Where the runtime provides the FIPS 203/204/205
primitives through OpenSSL, that is what executes. The JavaScript
implementation is the documented fallback for everything else, browsers
included.

Asked directly on the operational environment named in section 2:

```
backend() -> { kind: 'openssl', library: 'node:crypto', openssl: '3.5.6' }
```

A certificate against the JavaScript implementation would therefore certify a
path that a supported deployment does not take. That is the wrong way round,
and it is why we want the native path quoted.

**What we do not have for it.** No graded evidence, none. Everything in
section 2 is the JavaScript implementation:
`conformance/acvts/responders.mjs` binds to `@noble/post-quantum` directly
instead of going through the backend selector, and the ACVTS registration
names that library by version. Certificate A11025, and the 2,130 cases per
validation record 42204 in section 2, are that path and only that path. The
native path has never been run against ACVTS.

Note what follows from those two facts together. On the same machine that
produced the certified evidence, the library in ordinary use would have run
OpenSSL. The evidence and the deployment do not meet.

**We tried to close that gap ourselves and could not, which is the useful part.**
`conformance/acvts/responders-native.mjs` is an ACVP responder that answers with
OpenSSL instead of the JavaScript library. Run against the same pinned NIST
vector files, per `conformance/results/selftest-native.json`:

| Vector set | Matched | Mismatched | Refused |
|---|---|---|---|
| ML-KEM keyGen | 0 | 0 | 75 |
| ML-KEM encapDecap | 90 | 0 | 75 |
| ML-DSA keyGen | 0 | 0 | 75 |
| ML-DSA sigGen | 0 | 0 | 360 |
| ML-DSA sigVer | 45 | 0 | 135 |
| SLH-DSA keyGen | 0 | 0 | 120 |
| SLH-DSA sigGen | 0 | 0 | 624 |
| SLH-DSA sigVer | 42 | 0 | 462 |
| **Total** | **177** | **0** | **1926** |

Read both columns. **Nothing OpenSSL answered was wrong**, per that report: 177
matched and 0 mismatched against NIST's published expected results. What it
could not answer at all is the larger number, and it splits into two causes that
are not the same problem.

**Cause 1, the Node binding, roughly 60 groups.** ACVP does not want an answer,
it wants a reproducible one: a keygen driven from the seed NIST supplies, a
signature using the per-signature randomness NIST supplies. OpenSSL 3.5 takes
those controls at its C API. Node's binding does not pass them on. Read out of
Node's own source, `crypto.sign` looks for one algorithm-specific option on the
key object, `context`, and there is no `deterministic`, no `rnd` and no `mu`.
Node also ignores an unknown option in silence, so a harness that passed one
would appear to work and would be graded wrong. That accounts for 42 groups
refused on signing randomness, 9 on the internal interface, 9 on keygen where
only the seed can be exported rather than the expanded key, 3 on encapsulation
needing NIST's m, and 6 on pre-hash.

**Cause 2, the OpenSSL build, 90 groups.** The 9 SLH-DSA parameter sets named
above simply are not in it. No binding would help.

**So item 3 below is a question for you, not an offer from us.** A lab driving
OpenSSL through its C API should reach what we cannot reach through Node. We can
hand over the responder, the harness and this measurement. We cannot finish it
at this layer, and we would rather say so now than discover it inside a paid
engagement.

**What it changes about section 3.** OpenSSL 3.5.6 on this runtime provides 9
parameter sets: all 3 ML-KEM, all 3 ML-DSA, and 3 of the SLH-DSA sets, which
are SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192s and SLH-DSA-SHAKE-256f. The other 9
FIPS 205 sets have no native path and fall back to JavaScript. So a
native-only certificate covers the ML-KEM and ML-DSA scope in section 3 in
full, and 3 SLH-DSA sets rather than 12.

**What it changes about section 4.** The declined-pairing rule described there
is `@noble/post-quantum`'s policy. It does not carry across. The native path's
constraint is a different one and it is wider: pre-hash is not reachable at
all. The provider refuses it.

```
crypto.sign('sha256', message, mlDsaKey)
  -> error:1C80007A:Provider routines::invalid digest
```

Measured across ML-DSA-44, ML-DSA-65, ML-DSA-87 and the 3 native SLH-DSA sets,
against sha256, sha384, sha512 and shake256: **refused on 24 of 24 set and hash
pairs. Pure mode signs and verifies on 6 of 6.** FIPS 204 and FIPS 205 context
strings run natively, and are not affected.

So on the native path the 135-of-975 deviation in section 4 does not arise at
all. What arises instead is that NIST's pre-hash vector groups have no
implementation behind them on that path. Tell us how you would handle it:
scope the certificate to pure mode, or require pre-hash to come from
somewhere.

**How a deployment proves it stayed on the certified path.** A silent fallback
would mean the certificate describes an implementation the process did not
use, with nothing saying so. `requireNativeBackend()` is an operator control
that fails a process at import if it has landed on the JavaScript path, set
from the environment rather than from application code, because the team under
the control is usually not the team calling the library. It asserts that
OpenSSL is doing the arithmetic. Whether that OpenSSL is itself a validated
module is a property of the operator's build and the package does not claim to
see it.

**What we are asking you to price**

1. Algorithm validation of the native path, at the coverage above, pure mode.
2. The same for the JavaScript implementation, which already has graded
   evidence, if you would recommend certifying both rather than one.
3. Driving OpenSSL through its C API so the groups in cause 1 can be answered.
   Say plainly whether your harness does this today. If it does not, say so,
   because then the native path cannot be validated in full by anyone and that
   changes what we should certify.

**Version binding.** The demo certificate names 1.7.2. The current published
release is 1.7.3, which changed packaging metadata and added no algorithm, key
format or wire format change. Tell us whether you would validate against 1.7.2
as certified, or re-run against the current release, and what that costs.

## 6. What we can hand you on day one

- The full ACVTS client, in `conformance/acvts/`, with a README carrying every
  protocol trap we hit
- Both responders: the JavaScript one that produced certificate A11025, and the
  OpenSSL one in `responders-native.mjs`, which refuses a group it cannot
  express rather than answering it wrongly, and names the reason
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
