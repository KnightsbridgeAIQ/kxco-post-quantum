# Security Policy (draft): kxco-post-quantum/fips

**Status of this document.** This is a draft written in the structure NIST SP 800-140B Rev. 1 sets for a FIPS 140-3 Security Policy. It describes the module at the `kxco-post-quantum/fips` entry point. No testing laboratory has tested the module, and NIST has issued no CAVP or CMVP certificate for it. Where a section needs a laboratory's or NIST's decision, it says so.

Every statement below can be checked against the code in `src/fips/`, the tests in `test/fips.test.js`, or the script or command named where the statement is made.

## 1 General

### 1.1 Overview

`kxco-post-quantum/fips` is a software cryptographic module that offers post-quantum key establishment (ML-KEM, FIPS 203) and digital signatures (ML-DSA, FIPS 204) to Node.js applications. It is a separate entry point of the `kxco-post-quantum` npm package. Importing the main package does not load it, and importing it loads nothing from the main package.

### 1.2 Security levels

The module is designed against the Level 1 requirements in every area. Physical security does not apply to a software module. Non-invasive security and mitigation of other attacks are not claimed.

## 2 Cryptographic module specification

### 2.1 Description

- **Type:** software.
- **Embodiment:** multi-chip standalone, running on a general-purpose computer.
- **Cryptographic boundary:** the files in `src/fips/` of the installed package. Version 1.13.0 has 24 files: 7 module files, 13 code files copied from the noble libraries, their 3 licence files and `vendor/VENDOR.json`. The two files written at release, `integrity.json` and `integrity.json.sig`, are also in the boundary.
- **Tested operational environment's physical perimeter:** the general-purpose computer the module runs on.

The noble files are copied from `@noble/post-quantum` 0.7.1, `@noble/hashes` 2.4.0 and `@noble/curves` 2.4.0 by `scripts/vendor-fips.mjs`. The only lines that differ from upstream are import and export statements. `vendor/VENDOR.json` records the SHA-256 digest of each upstream file, and CI fails if the copies drift from the pinned versions.

### 2.2 Module version and identification

The module reports its name and version through `status()`. The version is the package version recorded in the signed manifest.

### 2.3 Excluded components

None. The module imports three Node.js built-ins, `node:fs`, `node:path` and `node:url`, which belong to the operational environment.

### 2.4 Modes of operation

The module has one mode, the approved mode. It offers no non-approved service, so it cannot be put into a non-approved mode.

### 2.5 Algorithms

| Algorithm | Standard | Use |
|---|---|---|
| ML-KEM-768, ML-KEM-1024 | FIPS 203 | key generation, encapsulation, decapsulation |
| ML-DSA-65, ML-DSA-87 | FIPS 204 | key generation, signature generation (hedged), signature verification |
| HMAC_DRBG with SHA-512 | SP 800-90A Rev. 1 | random bit generation |
| HMAC-SHA2-512 | FIPS 198-1 | inside HMAC_DRBG |
| SHA2-256 | FIPS 180-4 | integrity test |
| SHA2-512 | FIPS 180-4 | inside HMAC_DRBG |
| SHA3-256, SHA3-512, SHAKE128, SHAKE256 | FIPS 202 | inside ML-KEM and ML-DSA |

**Algorithm certificates.** None. Demo results are not a CAVP validation, and none of the sessions below has been taken through the Demo certification step.

**NIST's Demo test server.** On 28 October 2026, NIST's Demo server graded the module's own code, run on Node.js 26.12.1 on Debian 13 x86_64:
- Session 783218: HMAC_DRBG with SHA-512, passed.
- Session 783219: SHA2-256, SHA2-512, SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 and HMAC-SHA2-512, each passed.

Earlier, in September 2026, the Demo server graded the ML-KEM and ML-DSA code on another operating environment, Node.js 26.1.0 on Windows 10 (Demo certificate A11025). The registrations and the code that answers them are in `conformance/acvts/`.

**Our own runs of NIST's published vectors.** These use NIST's sample files at ACVP-Server commit 975de31e, pinned in `conformance/acvp-lock.json`.
- The ML-KEM and ML-DSA sets on the module's own copy of the code give 788 passed, 0 failed and 67 skipped (`node conformance/run-acvp.mjs --impl vendor --set ML-KEM-keyGen-FIPS203,ML-KEM-encapDecap-FIPS203,ML-DSA-keyGen-FIPS204,ML-DSA-sigGen-FIPS204,ML-DSA-sigVer-FIPS204`). The 67 skips are HashML-DSA pairings whose pre-hash is weaker than the parameter set, which the code refuses and the module does not offer.
- The SHA-2, SHA-3, SHAKE, HMAC and HMAC_DRBG sets give 2,252 cases matched and 0 mismatched, 15 of them HMAC_DRBG SHA-512 (source: `node conformance/acvts/selftest-fips.mjs`, run 28 October 2026). Cases outside the registration, such as messages that are not whole bytes, are counted separately and not as passes.

### 2.6 Security function implementations

- **Key establishment:** ML-KEM encapsulation and decapsulation. The shared secret is 256 bits.
- **Digital signature:** ML-DSA, pure mode, with an optional context string of at most 255 bytes. Pre-hash (HashML-DSA) is not offered.

### 2.7 Algorithm-specific information

- **ML-DSA signing** is the hedged variant (FIPS 204 Algorithm 2). The 32 bytes of signing randomness come from the module's DRBG.
- **ML-KEM inputs** are checked as FIPS 203 sections 7.2 and 7.3 require, by the noble implementation. A malformed key is refused with an exception and is not used. NIST's encapsulation-key and decapsulation-key check groups pass within the 788 above, and `test/fips.test.js` checks a malformed encapsulation key, a decapsulation key with a corrupted hash and a short ciphertext.
- **A ciphertext that does not decapsulate correctly** returns the implicit-rejection secret that FIPS 203 specifies, not an error.

### 2.8 RBG and entropy

- **RBG:** HMAC_DRBG with SHA-512, security strength 256 bits, without prediction resistance (`src/fips/drbg.js`). A request returns at most 65,536 bytes, which is the SP 800-90A Table 2 maximum of 2^19 bits (source: `MAX_BYTES_PER_REQUEST` in `src/fips/drbg.js`; NIST SP 800-90A Rev. 1, Table 2). The module reseeds after 2^20 requests, far below the SP 800-90A maximum of 2^48.
- **Entropy source:** the operating system's random device, `/dev/urandom`, read directly with a file read (`src/fips/entropy.js`). The module does not use `crypto.getRandomValues` or `crypto.randomBytes`, which in Node.js are OpenSSL's `RAND_bytes`. The source is outside the cryptographic boundary.
- **Entropy requested:** 48 bytes (384 bits) of entropy input at instantiation and at each reseed, and a 32-byte (256-bit) nonce at instantiation. The personalisation string is fixed: `kxco-post-quantum/fips HMAC_DRBG v1`.
- **RBG output is used for:** ML-KEM key generation seeds (64 bytes), ML-DSA key generation seeds (32 bytes), ML-KEM encapsulation randomness (32 bytes), ML-DSA signing randomness (32 bytes), and the randomness inside the pairwise consistency tests.
- **Entropy caveat:** the entropy rules in IG 9.3.A govern this. Case 1(b) applies if the operating system's source is an SP 800-90B entropy source within the tested environment. Case 1(c) applies if it is treated as a source outside it. Which case applies is for a testing laboratory to decide. Until then the module states the case 1(c) caveat through `status().caveat`: "No assurance of the minimum strength of generated SSPs (e.g., keys)."

### 2.9 Key generation

Key pairs are generated from a seed taken directly from the approved DRBG, as SP 800-133 Rev. 2 section 4 describes. The seed is 64 bytes, d and z, for ML-KEM (FIPS 203 section 7.1) and 32 bytes, ξ, for ML-DSA (FIPS 204 Algorithm 1). A pairwise consistency test runs on every generated key pair before it is returned.

`keypairFromSeed` re-expands a stored seed. For a seed the module generated, this is reconstitution and needs no new pairwise test (IG 10.3.A, Additional Comment 1). The module does not offer HKDF-derived key generation: FIPS 204 section 3.6.1 requires the seed to be "a fresh (i.e., not previously used) random value generated using an approved RBG", and FIPS 203 section 3.3 sets the same rule.

### 2.10 Key establishment

ML-KEM is a key encapsulation mechanism. The module does not perform key agreement with any other algorithm, or key transport.

### 2.11 Industry protocols

None.

## 3 Cryptographic module interfaces

### 3.1 Ports and interfaces

| Logical interface | Implementation |
|---|---|
| Data input | arguments of the service functions |
| Data output | return values of the service functions |
| Control input | the import of the module and calls to its functions |
| Status output | `status()`, and exceptions with code `ERR_KXCO_PQ_FIPS` |

There is no control output interface and no power interface.

## 4 Roles, services and authentication

### 4.1 Authentication methods

None. Level 1 does not require authentication.

### 4.2 Roles

One role, the Crypto Officer. The operator assumes it implicitly by importing the module.

### 4.3 Approved services

Each service is available only while the module is in the operational state, except `status()` and `zeroize()`.

- **`status()`:** reports the module name, version, state, the reason for an error state, the entropy caveat and the algorithms offered. It uses no SSP.
- **`selfTest()`:** runs the pre-operational self-tests and every algorithm self-test again. It uses the release public key.
- **`generateKeypair(alg)`:** generates an ML-KEM or ML-DSA key pair from a DRBG seed and runs the pairwise test. It returns the public key, the private key and the seed.
- **`keypairFromSeed(alg, seed)`:** expands a seed into its key pair.
- **`encapsulate(alg, publicKey)`:** ML-KEM encapsulation, with randomness from the DRBG. It returns the ciphertext and the shared secret.
- **`decapsulate(alg, cipherText, secretKey)`:** ML-KEM decapsulation. It returns the shared secret.
- **`sign(alg, secretKey, message, { context })`:** hedged ML-DSA signature generation, with randomness from the DRBG.
- **`verify(alg, publicKey, message, signature, { context })`:** ML-DSA signature verification. It returns `true` or `false`.
- **`zeroize(...buffers)`:** overwrites the given buffers with zeros.

Indicator: implicit. The module offers only approved services, so a call that returns has run as an approved service (IG 2.4.C).

### 4.4 Non-approved services

None.

### 4.5 External software and firmware loaded

None. The module loads code only from its own boundary. The services, and the code only they use, load after the integrity test has passed. The code that performs the integrity test runs before it, because it must: `index.js`, `selftest.js`, `kat.js`, `release-key.js` and the vendored SHA-2 and ML-DSA code. The integrity test then checks those files as well.

## 5 Software and firmware security

### 5.1 Integrity techniques

At release, `scripts/build-fips-manifest.mjs` writes `integrity.json`, which holds the SHA-256 digest of every file in the boundary. `publish.yml` then signs it with the ML-DSA-87 release key. On import, the module checks three things:
- the signature verifies under the release public key embedded in `release-key.js`;
- every file listed is present and matches its digest;
- no file is present that the manifest does not list.

The module also refuses to run from anything other than a local file.

The code that performs this test, listed in section 4.5, runs before the test does, so the test cannot vouch for that code before it runs. It detects a change to any file, those files included, as soon as it runs. The manifest records the package version, but the module accepts any manifest the release key signed. So the test shows that the files are an unmodified KXCO release, not which release they are.

### 5.2 Initiate on demand

`selfTest()` runs the integrity test again, with the algorithm self-tests.

### 5.3 Open-source parameters

The module is open source under Apache-2.0. The noble code it carries is MIT-licensed, and its licence files are inside the boundary.

## 6 Operational environment

### 6.1 Type and requirements

Modifiable. The module runs on Node.js and needs `/dev/urandom`. It has been tested on Linux only. On Windows, which has no `/dev/urandom`, it stays in the error state.

- **First environment to claim:** Node.js 26 on Linux x86_64.
- **Developer testing so far:**
  - Node.js 26.12.1 on Debian 13 (trixie) x86_64, in the `node:26` container image;
  - Node.js 22.23.4 on Debian 12 (bookworm) x86_64, in the `node:22` container image;
  - GitHub's Ubuntu runners for Node.js 22, 24 and 26, in CI.

## 7 Physical security

Not applicable to a software module.

## 8 Non-invasive security

Not claimed.

## 9 Sensitive security parameter management

### 9.1 Storage areas

Process memory only. The module stores no SSP persistently. Keys the operator wants to keep are returned to the operator, who stores them.

### 9.2 SSP input and output

Plaintext, through the function arguments and return values, as Level 1 permits.

### 9.3 Zeroisation

- **Overwritten by the module as soon as used:**
  - the entropy input and nonce after instantiation, and the entropy input after each reseed;
  - each superseded DRBG K and V value;
  - the encapsulation randomness and the signing randomness;
  - the values inside the pairwise tests.
- **Destroyed on entering the error state:** the DRBG state (SP 800-90A uninstantiate).
- **Held by the operator:** overwritten by the operator with `zeroize()`.

Copies that the JavaScript engine makes on its own, during garbage collection or compilation, are beyond the module's reach. Zeroising temporary SSPs is a Level 2 to 4 requirement (AS09.32).

### 9.4 SSPs

| SSP | Type | Generated or entered | Zeroised |
|---|---|---|---|
| DRBG entropy input and nonce | CSP | from `/dev/urandom` | after use |
| DRBG internal state (K, V) | CSP | by HMAC_DRBG | superseded values on each update; all on error |
| ML-KEM seed and decapsulation key | CSP | DRBG, or entered via `keypairFromSeed` | by the operator |
| ML-KEM encapsulation key | PSP | derived from the seed, or entered | not required |
| ML-KEM shared secret | CSP | encapsulation or decapsulation | by the operator |
| ML-KEM encapsulation randomness | CSP | DRBG | after use |
| ML-DSA seed and private key | CSP | DRBG, or entered via `keypairFromSeed` | by the operator |
| ML-DSA public key | PSP | derived from the seed, or entered | not required |
| ML-DSA signing randomness | CSP | DRBG | after use |
| Release public key (ML-DSA-87) | PSP | embedded in `release-key.js` | not required |

## 10 Self-tests

### 10.1 Pre-operational self-tests

On import, in this order:
1. Algorithm self-tests for SHA2-256 and for ML-DSA-87 signature verification, because the integrity test uses both (IG 10.2.A).
2. The integrity test in section 5.1.

### 10.2 Conditional self-tests

**Algorithm self-tests.** These run after the integrity test and before any service is offered (`src/fips/selftest.js`).
- SHA2-512 and HMAC-SHA2-512.
- HMAC_DRBG instantiate, reseed and generate, per SP 800-90A section 11.3.
- ML-KEM-1024 key generation, encapsulation, decapsulation and implicit rejection.
- ML-DSA-87 key generation and signature generation.

Every known answer is taken from NIST's ACVP vector files, which `conformance/acvp-lock.json` pins by digest. `scripts/build-fips-kat.mjs` regenerates `src/fips/kat.js` from them byte for byte, and CI checks it. One test per algorithm covers all of its parameter sets (IG 10.3.A).

**Pairwise consistency tests.** These run on every generated key pair. For ML-KEM: encapsulate to the new public key, decapsulate, and compare. For ML-DSA: sign a fixed message with the new key and verify the signature.

### 10.3 Periodic self-tests

None scheduled. The operator can run them at any time with `selfTest()`.

### 10.4 Error states

The module has one error state. It enters it when any self-test fails, when the integrity test fails, or when the DRBG or the entropy source fails.

In the error state, every cryptographic service throws an exception with code `ERR_KXCO_PQ_FIPS`, and the DRBG state is destroyed. `status()` reports `state: 'error'` and the reason. The module leaves the error state only when the process restarts.

`test/fips.test.js` produces each of these failures and checks the result:
- a changed file, an extra file, and a manifest signed by another key;
- a wrong known answer before the integrity test (SHA-256) and after it (ML-KEM-1024, HMAC_DRBG);
- a failing ML-KEM pairwise test and a failing ML-DSA pairwise test;
- a missing entropy source.

### 10.5 Operator initiation of self-tests

`selfTest()`.

## 11 Life-cycle assurance

### 11.1 Installation, initialisation and start-up

1. Install the package from npm. Releases are published from GitHub Actions with npm provenance, which `npm audit signatures` checks.
2. Import `kxco-post-quantum/fips`. The self-tests run on import.
3. Check that `status().state` is `'operational'` before using any service.

### 11.2 Administrator guidance

- Store generated seeds and private keys securely, and zeroise them with `zeroize()` when they are no longer needed.
- Do not edit, add or remove files in the installed package's `src/fips/` directory, or the integrity test will fail.
- Do not bundle the module. It must run from its installed files.

### 11.3 Non-administrator guidance

There is no other role.

## 12 Mitigation of other attacks

None claimed. In particular, the module makes no constant-time or side-channel claim. See `THREAT-MODEL.md`.
