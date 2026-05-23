# Changelog

## 1.1.4 — 2026-05-24

Maintenance release. No breaking changes.



## 1.1.3 â€” 2026-05-23

Maintenance release. No breaking changes.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] â€” 2026-05-22

Documentation correction. No code changes; no behaviour changes; no
cryptographic surface changes vs `1.1.1`.

### Fixed
- **AUDIT.md** Â§1 previously cited a 2024 Cure53 audit of
  `@noble/post-quantum`. That citation was incorrect â€” Cure53's 2023
  NDS-01 audit covered `@noble/ciphers`, `@noble/curves`, and
  `@noble/hashes` only; the post-quantum package was not in scope. As of
  2026-05-22, upstream `@noble/post-quantum` has only been self-audited
  by its maintainer (v0.6.1, April 2026). AUDIT.md Â§1 has been rewritten
  to reflect the actual upstream audit posture. A correction notice is
  included at the top of the file. Reviewers who relied on the prior
  citation should re-read Â§1 of AUDIT.md.
- **CHANGELOG.md** 1.0.0 entry similarly stated "audited by Cure53,
  2024" alongside the upstream pin. That sentence has been corrected
  in-place in this release; the substance of the 1.0.0 release is
  otherwise unchanged.

### Why this is a patch, not an advisory
The misstatement was in documentation only. No code path, signature,
key-derivation routine, or wire format depends on the cited audit. The
fix is a documentation rewrite; affected installs upgrade by pulling
1.1.2. If your due-diligence pack referenced AUDIT.md from 1.0.1
through 1.1.1, please refresh against 1.1.2.

## [1.1.1] â€” 2026-05-21

Operational hardening release. No source-code changes; this is the first
release published via **npm Trusted Publishing** rather than a long-lived
`NPM_TOKEN`.

### Changed
- `.github/workflows/publish.yml` now publishes via npm Trusted Publishing
  (OIDC). The `NODE_AUTH_TOKEN` / `NPM_OTP` env vars are removed; the
  workflow's `id-token: write` permission is the entire credential.
  Registered at https://www.npmjs.com/package/kxco-post-quantum/access
  binding `org=JackKXCO`, `repo=kxco-post-quantum`, `workflow=publish.yml`.
- Repo-level `NPM_TOKEN` and `NPM_OTP` secrets removed â€” no long-lived
  credentials remain in the publishing path.

### Why this matters
- Every release tarball is now signed by GitHub Actions OIDC against the
  exact commit being published, with no human-held secret in the loop.
- No more burning recovery codes per release. The publish workflow now
  runs hands-free on every `v*` tag push.

## [1.1.0] â€” 2026-05-21

Same API. Same byte-for-byte outputs (all 29 pinned vectors still match).
The package now runs in **browsers** as well as Node.

### Added
- Isomorphic runtime â€” every module works identically in modern browsers
  (Chromium, Firefox, Safari) and Node, served from CDNs like esm.sh
  with zero polyfill burden
- `test/browser-smoke.test.js` runs the public API with `globalThis.Buffer`
  removed, asserts plain `Uint8Array` outputs and a clean hybrid-signing
  round trip â€” proves browser compatibility in CI

### Changed
- HKDF-SHA-512 now sourced from `@noble/hashes/hkdf` (was `node:crypto`)
- HMAC-SHA-256 now sourced from `@noble/hashes/hmac` (was `node:crypto`)
- SHA-256 for kid fingerprints now sourced from `@noble/hashes/sha256`
  (was `node:crypto`)
- Constant-time comparisons are portable byte loops (replaces
  `node:crypto.timingSafeEqual`) â€” identical security property,
  runs in browsers
- Functions return `Buffer` on Node (when `globalThis.Buffer` is defined)
  and plain `Uint8Array` in browsers. **Backwards compatible** for Node
  callers; `Buffer extends Uint8Array` so any code accepting `Uint8Array`
  already works.
- `engines.node` bumped to `>=20.19` to match the underlying
  `@noble/hashes@2` requirement (Node 18 is past EOL)

### Dependencies
- Added `@noble/hashes ^2.2.0` (peer of `@noble/post-quantum`)
- `@noble/post-quantum ^0.2.1` unchanged

### Verification
- 9 node tests pass
- 6 browser-smoke tests pass
- 29 pinned vectors still match â€” no cryptographic surface changes,
  bit-for-bit identical to 1.0.3 in Node

## [1.0.3] â€” 2026-05-21

First release ships with SLSA Level 2 provenance attestation tied to a
public GitHub Actions workflow run. No cryptographic surface changes
vs `1.0.2` â€” every diff is metadata, types, CI, and hygiene.

### Added
- SLSA Level 2 provenance on every published release via GitHub Actions OIDC
  (`publishConfig.provenance: true`)
- `.github/workflows/publish.yml` triggered by `v*` tags â€” runs tests then
  `npm publish --provenance --access public`
- `.github/workflows/ci.yml` matrix over Node 18 / 20 / 22 on every push and PR
- Hand-written TypeScript declarations (`.d.ts`) for all six modules; wired
  into `exports[*].types` so TypeScript consumers get full typings without
  any build step
- `.github/dependabot.yml` â€” weekly npm + github-actions ecosystem checks
- `sideEffects: false` for tree-shaking
- `funding` field in `package.json`
- Top-level `"types"` field in `package.json` pointing at `./src/index.d.ts`

### Changed
- `package.json` `files` allowlist tightened to `["src", "README.md", "LICENSE",
  "SECURITY.md", "CHANGELOG.md"]` â€” locks down what ships to npm
- `package.json` `exports` now declares per-subpath `types` + `import` keys
- `SECURITY.md` rewritten in the standard short-form template with explicit
  in-scope / out-of-scope split delegating primitive bugs upstream to
  `@noble/post-quantum`
- All third-party actions in workflows pinned by 40-char commit SHA, never
  floating tags
- README badge row trimmed to four (`npm`, `license`, `Socket`, `production-live`)
  and a 60-second live-verify quickstart added under the title

### Security
- No cryptographic code changed in this release â€” every change is metadata,
  types, CI, and documentation. Production behaviour is bit-for-bit identical
  to `1.0.2`.

## [1.0.2] â€” 2026-05-21

### Changed
- Repository URL on the npm package metadata now points to
  `github.com/JackKXCO/kxco-post-quantum`. No code change.

## [1.0.1] â€” 2026-05-21

### Added
- `AUDIT.md` â€” self-attested audit posture with roadmap (external audit
  Q3 2026, public bug bounty Q4 2026, FIPS 140-3 CMVP application 2027)
- `test/vectors.json` â€” 29 deterministic test vectors pinning every primitive
  output bit-for-bit
- `test/run-vectors.js` â€” runner anyone can use to verify reproducibility
- `npm test` runs both the functional tests and vector verification
- `npm run test:vectors` for vector check only

### Changed
- `SECURITY.md` sharpened with explicit threat model and pinned upstream
  `@noble/post-quantum@0.2.1` integrity hash
- `README.md` "Used in production at" section with file refs to chain.kxco.ai

No API changes from `1.0.0`.

## [1.0.0] â€” 2026-05-21

First stable release. Committed public API surface:

- `mlDsa.keypairFromMaster(master, info—)`, `mlDsa.sign`, `mlDsa.verify`
- `mlKem.keypairFromMaster(master, info—)`, `mlKem.encapsulate`, `mlKem.decapsulate`
- `deriveSeed(master, info, length)`
- `fingerprint(publicKey)`, `kidEquals(a, b)`
- `webhook.envelope`, `webhook.hmacHex`, `webhook.verifyHmac`,
  `webhook.pqSign`, `webhook.verifyPq`, `webhook.signDelivery`,
  `webhook.verifyDelivery`

Verified at release: 9/9 functional tests + 29/29 vector checks pass.

Underlying primitives via `@noble/post-quantum@^0.2.1`. See `AUDIT.md` for
upstream audit posture (no third-party audit of the PQ package; self-audited
by maintainer at v0.6.1, April 2026). ESM-only. Node.js 18+.

## [0.1.0] â€” 2026-05-21

Initial pre-release.

[Unreleased]: https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.2...HEAD
[1.1.2]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.1...v1.1.2
[1.1.1]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.0...v1.1.1
[1.1.0]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.3...v1.1.0
[1.0.3]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.2...v1.0.3
[1.0.2]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.1...v1.0.2
[1.0.1]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.0...v1.0.1
[1.0.0]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v0.1.0...v1.0.0
[0.1.0]:      https://github.com/JackKXCO/kxco-post-quantum/releases/tag/v0.1.0