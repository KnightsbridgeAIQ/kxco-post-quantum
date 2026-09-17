# ACVTS: testing against NIST's live server

`conformance/run-acvp.mjs` runs NIST's **published** vector files, pinned by
commit and per-file digest. This directory does the other half: it speaks the
live ACVP protocol to **NIST's own server**, which sends vectors nobody has seen
and grades the answers itself.

Both matter. The pinned files prove we agree with what NIST published. The live
server proves we agree with what NIST computes today, over the protocol a real
validation uses.

## Why it exists

A CAVP algorithm certificate is issued only from the ACVTS **Production**
server, and NIST restricts Production to NVLAP-accredited laboratories. Before
anyone, lab or vendor, may run an algorithm in Production, they must have taken
that algorithm **through the certification step in Demo at least once**. This
directory is how we do that, and the demo certificate numbers it produces are
the entry ticket either way we go.

## Credentials

Outside this repository, in `C:\Users\ADMIN\.credentials\acvts\`, with the login
mechanics recorded in `CREDENTIALS.md` beside them. Nothing here writes a
credential to disk or to a log. NIST's covering letter is explicit that the
certificate, private key and TOTP seed are each secret.

Override the location with `ACVTS_CRED_DIR`, and the host with `ACVTS_HOST`.

## Running it

```
node conformance/acvts/selftest.mjs                       # offline gate, run this first
node conformance/acvts/run-session.mjs <name>[,<name>] [--sample] [--keep DIR]
node conformance/acvts/create-resources.mjs <stateFile>   # once per vendor
node conformance/acvts/publish.mjs <keepDir> <stateFile>  # the certification step
```

Registration names are the keys of `REGISTRATIONS` in `registrations.mjs`:
`ml-kem-keygen`, `ml-kem-encapdecap`, `ml-dsa-keygen`, `ml-dsa-siggen`,
`ml-dsa-sigver`, `slh-dsa-keygen`, `slh-dsa-siggen`, `slh-dsa-sigver`.

**Run `selftest.mjs` before any live session.** It puts the responder against the
pinned vectors, which carry expected answers, and compares field by field. New
code that generates answers for a grader should be proved against answers we
already have, offline, before it is sent to a US government system.

**Always pass `--keep`.** A session carries its own access token, returned once
at registration. The login token returns **403** on a session URL, so a session
that was not kept cannot be certified afterwards from anywhere.

## What we claim, and what we do not

The registration is narrower than NIST's example, deliberately.

The JavaScript backend refuses a HashML-DSA or HashSLH-DSA pre-hash whose
collision strength is below the parameter set's security category: SHA2-224 with
ML-DSA-44, SHA2-384 with ML-DSA-87, and so on. That is the backend's policy, not
a FIPS 204 or FIPS 205 requirement, and NIST's own vector files pair every hash
with every parameter set. So `registrations.mjs` derives the pre-hash list per
parameter set from the same strength rule the backend enforces, and we claim only
what we can answer. In the pinned files that accounts for 135 test cases the
backend declines out of 975.

`selftest.mjs` reports every refusal by group, parameter set and reason. That
list is the claim boundary, and it belongs in any report of these results.

Offline gate as run on 13 September 2026: **1,176 matched, 0 mismatched, 303
refused**, across seven of the eight pinned sets. `SLH-DSA-sigGen-FIPS205` is the
exception and is not run offline: it costs about an hour of signing, and the live
server has already graded the same computation and passed it.

## Things about this server that are not guessable

- **A TOTP value is accepted once.** Two logins inside the same 30-second window
  return HTTP 200 with **no `accessToken` in the body**, which reads exactly like
  a broken credential. `login()` waits for the next window instead.
- **Sessions carry their own token.** See `--keep` above.
- **Prompts are not ready when the session is created.** The vector set URL
  answers 200 with a status rather than test groups until the generator has run.
- **Resource creation is asynchronous.** `POST /acvp/v1/vendors` and friends
  return `/acvp/v1/requests/{id}`, not the resource. Poll the request until it is
  approved, then read the resource URL off it.
- **A session JWT expires on a clock, not on idleness.** SLH-DSA sigGen ran past
  it and the submit came back 401 after an hour of signing. `refresh()` renews it
  by posting the dead token alongside a fresh TOTP, and `--resume` submits the
  kept answer instead of recomputing. Note the renewal needs its **own** TOTP
  window: called straight after a login it returns 403, and succeeds 30 seconds
  later.
- **Keep-alive is off on purpose.** SLH-DSA signing runs for minutes between
  calls and a pooled socket is dead by the time the next request reuses it. The
  failure arrives as `ECONNRESET` on a POST that never left, which looks like
  rejection and is not.
- **Do not guess a payload shape. Ask.** POST an empty body and the server names
  every missing field. That is how the registrations and resource records here
  were derived, rather than from the spec drafts, which differ from what the
  server actually enforces. One real example: NIST's published `contextLength`
  example is accepted, but `{min: 0, max: 255, increment: 8}` is rejected with
  "min - max mod increment must be 0".

## Results, 12 and 13 September 2026

Against `demo.acvts.nist.gov`, non-sample sessions, `kxco-post-quantum` 1.7.2 on
`@noble/post-quantum` 0.7.0, Node.js 26.1.0.

| Session | Vector sets | Cases | Result |
| --- | --- | --- | --- |
| 767289 | ML-KEM keyGen, ML-KEM encapDecap, ML-DSA keyGen, ML-DSA sigGen, ML-DSA sigVer | 882 | all passed, publishable |
| 767291 | SLH-DSA keyGen, SLH-DSA sigVer | 624 | all passed, publishable |
| 767292 | SLH-DSA sigGen | 624 | all passed, publishable |

2,130 test cases graded by NIST, zero failures. Every algorithm KXCO ships is
covered: FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, in every parameter
set NIST offers, key generation, signing and verification.

All three sessions were then taken through the certification step and approved
onto one record:

**Demo certificate `A11025`**, validation `/acvp/v1/validations/42204`, module
`kxco-post-quantum 1.7.2 (Software)`, environment
`Node.js 26.1.0 on Windows 10 Pro 22H2, Intel Core i7-7700K`.

That number is what NIST asks to be quoted when Production access is requested.
It is a **Demo** certificate: it is not a CAVP validation, it does not appear on
the public algorithm validation list, and it is not a NIST certification of the
firm. What it proves is that these algorithms have been taken through a full
validation on NIST's own infrastructure and passed.

Re-read it from the server rather than from this file:

```
node conformance/acvts/verify-demo-certificate.mjs 42204
```
