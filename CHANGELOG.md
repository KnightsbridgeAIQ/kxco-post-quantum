# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SLSA Level 2 provenance on every published release via GitHub Actions OIDC
  (`publishConfig.provenance: true`)
- `.github/workflows/publish.yml` triggered by `v*` tags — runs tests then
  `npm publish --provenance --access public`
- `.github/workflows/ci.yml` matrix over Node 18 / 20 / 22 on every push and PR
- Hand-written TypeScript declarations (`.d.ts`) for all six modules; wired
  into `exports[*].types` so TypeScript consumers get full typings without
  any build step
- `.github/dependabot.yml` — weekly npm + github-actions ecosystem checks
- `sideEffects: false` for tree-shaking
- `funding` field in `package.json`
- Top-level `"types"` field in `package.json` pointing at `./src/index.d.ts`

### Changed
- `package.json` `files` allowlist tightened to `["src", "README.md", "LICENSE",
  "SECURITY.md", "CHANGELOG.md"]` — locks down what ships to npm
- `package.json` `exports` now declares per-subpath `types` + `import` keys
- `SECURITY.md` rewritten in the standard short-form template with explicit
  in-scope / out-of-scope split delegating primitive bugs upstream to
  `@noble/post-quantum`
- All third-party actions in workflows pinned by 40-char commit SHA, never
  floating tags
- README badge row trimmed to four (`npm`, `license`, `Socket`, `production-live`)
  and a 60-second live-verify quickstart added under the title

### Security
- No cryptographic code changed in this release — every change is metadata,
  types, CI, and documentation. Production behaviour is bit-for-bit identical
  to `1.0.2`.

## [1.0.2] — 2026-05-21

### Changed
- Repository URL on the npm package metadata now points to
  `github.com/JackKXCO/kxco-post-quantum`. No code change.

## [1.0.1] — 2026-05-21

### Added
- `AUDIT.md` — self-attested audit posture with roadmap (external audit
  Q3 2026, public bug bounty Q4 2026, FIPS 140-3 CMVP application 2027)
- `test/vectors.json` — 29 deterministic test vectors pinning every primitive
  output bit-for-bit
- `test/run-vectors.js` — runner anyone can use to verify reproducibility
- `npm test` runs both the functional tests and vector verification
- `npm run test:vectors` for vector check only

### Changed
- `SECURITY.md` sharpened with explicit threat model and pinned upstream
  `@noble/post-quantum@0.2.1` integrity hash
- `README.md` "Used in production at" section with file refs to chain.kxco.ai

No API changes from `1.0.0`.

## [1.0.0] — 2026-05-21

First stable release. Committed public API surface:

- `mlDsa.keypairFromMaster(master, info?)`, `mlDsa.sign`, `mlDsa.verify`
- `mlKem.keypairFromMaster(master, info?)`, `mlKem.encapsulate`, `mlKem.decapsulate`
- `deriveSeed(master, info, length)`
- `fingerprint(publicKey)`, `kidEquals(a, b)`
- `webhook.envelope`, `webhook.hmacHex`, `webhook.verifyHmac`,
  `webhook.pqSign`, `webhook.verifyPq`, `webhook.signDelivery`,
  `webhook.verifyDelivery`

Verified at release: 9/9 functional tests + 29/29 vector checks pass.

Underlying primitives via `@noble/post-quantum@^0.2.1` (audited by Cure53, 2024).
ESM-only. Node.js 18+.

## [0.1.0] — 2026-05-21

Initial pre-release.

[Unreleased]: https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.2...HEAD
[1.0.2]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.1...v1.0.2
[1.0.1]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.0...v1.0.1
[1.0.0]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v0.1.0...v1.0.0
[0.1.0]:      https://github.com/JackKXCO/kxco-post-quantum/releases/tag/v0.1.0
