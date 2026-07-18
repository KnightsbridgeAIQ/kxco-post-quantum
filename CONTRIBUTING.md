# Contributing to kxco-post-quantum

Thanks for your interest. This package is used in production at KXCO, so we
keep the surface small and the bar for changes high. Bug fixes, test-vector
additions, and documentation improvements are very welcome.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting channel.

## Development setup

```bash
git clone https://github.com/KnightsbridgeAIQ/kxco-post-quantum.git
cd kxco-post-quantum
npm ci
npm test
```

Requires Node.js 20.19 or newer. The package is ESM-only.

## Running tests

```bash
npm test                # basic + browser smoke + reference vectors
npm run test:vectors    # vectors only
npm run bench           # micro-benchmark
```

The reference test vectors in [test/vectors.json](test/vectors.json) are
deterministic and pinned. If you change anything in `src/derive.js`,
`src/ml-dsa.js`, or `src/ml-kem.js`, regenerate them with
`npm run generate:vectors` and commit the result in the same PR.

## Pull requests

1. Branch off `main`.
2. Keep PRs focused — one logical change per PR.
3. Add or update tests for any behaviour change. Cryptographic code without a
   test vector won't be merged.
4. Run `npm test` locally and make sure it passes on Node 20, 22, and 24.
5. Open the PR. CI must pass and a code owner must review.

## Commit messages

We use Conventional Commits–style prefixes (`feat:`, `fix:`, `docs:`,
`deps:`, `ci:`, `chore:`). Keep the subject under 72 characters.

## Releases

Releases are cut from `main` by pushing a `v*` tag. The
[publish workflow](.github/workflows/publish.yml) handles npm via Trusted
Publishing (OIDC) — there are no long-lived npm tokens. Provenance is
attached automatically.

## Coding conventions

- ESM only. No CommonJS exports.
- No runtime dependencies beyond `@noble/post-quantum` and `@noble/hashes`.
- Zero side effects at import time — verified by `"sideEffects": false`.
- Use `const` and arrow functions; no classes unless absolutely required.
- Constant-time primitives must stay inside `@noble/*`. Don't roll your own.

## Questions

Open a discussion or email `hello@kxco.ai`.
