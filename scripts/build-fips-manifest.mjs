#!/usr/bin/env node
// Write src/fips/integrity.json, the manifest the FIPS module's integrity test
// checks: the SHA-256 digest of every file in src/fips/ except the manifest and
// its signature.
//
//   node scripts/build-fips-manifest.mjs [dir]
//
// The release workflow runs this, then signs the manifest with the ML-DSA-87
// release key (scripts/sign-release.mjs src/fips/integrity.json), immediately
// before publishing. The module refuses to run without a manifest that verifies
// under that key, so an unsigned checkout of the repository never runs it.
// `dir` defaults to src/fips; the tests pass a copy.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DIR = resolve(process.argv[2] ?? join(ROOT, 'src', 'fips'))
const SKIP = new Set(['integrity.json', 'integrity.json.sig'])

function filesIn(dir) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...filesIn(p))
    else out.push(relative(DIR, p).split(sep).join('/'))
  }
  return out
}

const files = {}
for (const f of filesIn(DIR).filter((f) => !SKIP.has(f)).sort()) {
  files[f] = createHash('sha256').update(readFileSync(join(DIR, ...f.split('/')))).digest('hex')
}
const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const manifest = { module: 'kxco-post-quantum/fips', version, files }
writeFileSync(join(DIR, 'integrity.json'), JSON.stringify(manifest, null, 2) + '\n')
console.log(`wrote ${relative(ROOT, join(DIR, 'integrity.json'))}: ${Object.keys(files).length} files, version ${version}`)
