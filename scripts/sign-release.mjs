#!/usr/bin/env node
// Sign release assets with ML-DSA-87, using this package's own signing path.
//
// A post-quantum signing library whose own releases carry only a classical
// signature is making an argument it does not act on. These are signed through
// the same `mlDsa87.sign` any caller uses, so the signature is evidence the
// library works as well as evidence the artefact is ours.
//
//   node scripts/sign-release.mjs <file> [<file>...]
//
// Reads the 32-byte master seed as hex from KXCO_RELEASE_SEED_87 and writes
// <file>.sig beside each input: the ML-DSA-87 signature over the file bytes, as
// hex. The key is derived under the label 'kxco-release-signing-87-v1'.
//
// Until KXCO_RELEASE_SEED_87 is configured, the script signs with the original
// ML-DSA-65 release key (KXCO_RELEASE_SEED), so a release is never left unsigned.
// Releases signed before the switch stay verifiable against
// release-signing-key.pub.hex.
//
// Verify an ML-DSA-87 signature with the public key in release-signing-key-87.pub.hex:
//
//   import { mlDsa87 } from 'kxco-post-quantum'
//   mlDsa87.verify(publicKeyBytes, fileBytes, sigHex)

import { readFileSync, writeFileSync } from 'node:fs'
import { mlDsa, mlDsa87 } from '../src/index.js'

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('usage: sign-release.mjs <file> [<file>...]')
  process.exit(2)
}

const seed87 = (process.env.KXCO_RELEASE_SEED_87 ?? '').trim()
const seed65 = (process.env.KXCO_RELEASE_SEED ?? '').trim()
const use87 = seed87 !== ''
const hex = use87 ? seed87 : seed65
if (!/^[0-9a-f]{64}$/i.test(hex)) {
  console.error(`${use87 ? 'KXCO_RELEASE_SEED_87' : 'KXCO_RELEASE_SEED'} must be 64 hex characters (a 32-byte master seed)`)
  process.exit(2)
}

const set = use87 ? mlDsa87 : mlDsa
const name = use87 ? 'ML-DSA-87' : 'ML-DSA-65'
const pubFile = use87 ? '../release-signing-key-87.pub.hex' : '../release-signing-key.pub.hex'
const kp = use87
  ? mlDsa87.keypairFromMaster(Buffer.from(hex, 'hex'), 'kxco-release-signing-87-v1')
  : mlDsa.keypairFromMaster(Buffer.from(hex, 'hex'))

// The published public key is committed to the repository. If the seed in CI
// ever stops matching it, every signature would verify against a key nobody
// has, which is worse than not signing. Fail instead.
const expected = readFileSync(new URL(pubFile, import.meta.url), 'utf8').trim()
const actual = Buffer.from(kp.publicKey).toString('hex')
if (actual !== expected) {
  console.error(`the seed does not derive the published ${name} release signing key; refusing to sign`)
  process.exit(1)
}

for (const file of files) {
  const bytes = readFileSync(file)
  const sig = set.sign(kp.secretKey, bytes)
  if (set.verify(kp.publicKey, bytes, sig) !== true) {
    console.error(`${file}: signature did not verify immediately after signing, refusing to publish it`)
    process.exit(1)
  }
  writeFileSync(`${file}.sig`, sig + '\n')
  console.log(`  ${file}.sig  (${sig.length / 2} bytes, ${name}, verified)`)
}
