// Build the CycloneDX 1.6 Cryptographic Bill of Materials for this package.
//
// WHY IT IS DECLARED RATHER THAN SCANNED. kxco-pq-scan emits CBOMs, but it
// reads a lock file, and a lock file says "@noble/post-quantum provides ML-DSA".
// It cannot say which parameter sets this package calls, that HKDF-SHA-512
// derives the seeds, that webhooks carry HMAC-SHA-256, or that the native
// backend generates throwaway keys to probe OpenSSL. Those are the rows the
// PQCMM Level 4 criterion asks for, so they are written down here.
//
// WHY A DECLARATION CAN BE TRUSTED ANYWAY. It is checked against the source on
// every build. `detect()` reads src/ for every place an algorithm is bound: an
// import from @noble, an entry in the native backend's algorithm table, a
// node:crypto call. The build refuses to emit a CBOM if the source binds an
// algorithm this file does not declare, or if a declared use no longer exists.
// A stale CBOM cannot be published; it fails `npm test` and the evidence build.
//
// WHAT IS IN IT. Three scopes, recorded on every asset as `kxco:scope`:
//   offered          reachable from the public API
//   internal         executed by the package but not offered: the native
//                    backend generates a throwaway key per OpenSSL algorithm at
//                    import, and signs with ML-DSA-44 to probe context support
//   release-pipeline not in the library at all, but part of how it reaches a
//                    user: the npm registry signature and Sigstore provenance,
//                    both classical. Leaving them out would overstate the posture.
//
// Key and signature sizes come from the implementation's own `lengths`, not
// from a table typed here, so they cannot drift from what the code produces.
//
// DETERMINISTIC. Nothing in the document depends on the Node version or on
// which backend is loaded, and the timestamp is SOURCE_DATE_EPOCH or the HEAD
// commit time, so both evidence legs produce identical bytes. The serial
// number is a UUID v5 over the content.
//
// Usage: node scripts/build-cbom.mjs [--out cbom.cyclonedx.json]

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import {
  slh_dsa_sha2_128f, slh_dsa_sha2_192s, slh_dsa_shake_256f,
} from '@noble/post-quantum/slh-dsa.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

const NOBLE_PQ = '@noble/post-quantum'
const NOBLE_HASHES = '@noble/hashes'
const OPENSSL = 'openssl'

const SIGN = ['keygen', 'sign', 'verify']
const KEM = ['keygen', 'encapsulate', 'decapsulate']

// Where each algorithm is bound in the source. `symbol` is matched literally
// against code with comments stripped, so a use mentioned only in a comment
// does not count as present.
const at = (location, symbol) => ({ location, symbol })

// The ML-KEM shared secret is 32 bytes for every FIPS 203 parameter set, and
// noble does not list it in `lengths`, so it is measured once here.
const sharedSecretBytes = (kem) =>
  kem.encapsulate(kem.keygen(new Uint8Array(kem.lengths.seed)).publicKey).sharedSecret.length

function sigSizes(impl) {
  const l = impl.lengths
  return { 'public-key': l.publicKey, 'private-key': l.secretKey, signature: l.signature, seed: l.seed }
}
function kemSizes(impl) {
  const l = impl.lengths
  return {
    'public-key': l.publicKey, 'private-key': l.secretKey, ciphertext: l.cipherText,
    'shared-secret': sharedSecretBytes(impl), seed: l.seed,
  }
}

const NATIVE_PROBE =
  'Native backend only (Node 24+ with OpenSSL 3.5). A throwaway key is generated at ' +
  'import to read the AlgorithmIdentifier OpenSSL uses. Not offered to callers.'

export const ASSETS = [
  // ── offered: the public API ────────────────────────────────────────────────
  {
    name: 'ML-DSA-65', scope: 'offered', primitive: 'signature', functions: SIGN,
    parameterSet: '65', oid: '2.16.840.1.101.3.4.3.18', nistLevel: 3,
    implementedBy: [NOBLE_PQ, OPENSSL], sizes: sigSizes(ml_dsa65),
    purpose: 'Signature scheme kept for existing keys: signing and verification ' +
      '(mlDsa), JWS alg ML-DSA-65, which a 4032-byte ML-DSA-65 secret key selects, ' +
      'the non-repudiation half of webhook delivery signing with an ML-DSA-65 key, ' +
      'and the release signature over assets and evidence bundles when no ML-DSA-87 ' +
      'release seed is configured.',
    context: 'Raw keys and signatures; RFC 9964 AKP JWK and seed-form PKCS#8; compact ' +
      'JWS; the X-KXCO-PQ-Signature webhook header, ml-dsa-65=<hex>.',
    occurrences: [
      at('src/ml-dsa.js', 'ml_dsa65'), at('src/seed.js', 'ml_dsa65'),
      at('src/jws.js', "'ML-DSA-65'"), at('src/webhook.js', 'mlDsaSign'),
      at('src/_native.node.js', "nodeName: 'ml-dsa-65'"),
      at('scripts/sign-release.mjs', 'mlDsa.keypairFromMaster'),
    ],
  },
  {
    name: 'ML-DSA-87', scope: 'offered', primitive: 'signature', functions: SIGN,
    parameterSet: '87', oid: '2.16.840.1.101.3.4.3.19', nistLevel: 5,
    implementedBy: [NOBLE_PQ, OPENSSL], sizes: sigSizes(ml_dsa87),
    purpose: 'Default signature scheme for new keys: signing and verification ' +
      '(mlDsa87), JWS alg ML-DSA-87, the signJws default for any key that is not ' +
      'an ML-DSA-65 secret key, the non-repudiation half of webhook delivery signing ' +
      'with an ML-DSA-87 key, and the release signature over assets and evidence ' +
      'bundles once the ML-DSA-87 release seed is configured (kid d35341d56b82c4bf).',
    context: 'Raw keys and signatures; RFC 9964 AKP JWK and seed-form PKCS#8; compact ' +
      'JWS; the X-KXCO-PQ-Signature webhook header, ml-dsa-87=<hex>.',
    occurrences: [
      at('src/ml-dsa-87.js', 'ml_dsa87'), at('src/seed.js', 'ml_dsa87'),
      at('src/jws.js', "'ML-DSA-87'"), at('src/webhook.js', 'mlDsa87Sign'),
      at('src/_native.node.js', "nodeName: 'ml-dsa-87'"),
      at('scripts/sign-release.mjs', 'mlDsa87.keypairFromMaster'),
    ],
  },
  {
    name: 'ML-KEM-768', scope: 'offered', primitive: 'kem', functions: KEM,
    parameterSet: '768', oid: '2.16.840.1.101.3.4.4.2', nistLevel: 3,
    implementedBy: [NOBLE_PQ, OPENSSL], sizes: kemSizes(ml_kem768),
    purpose: 'Default key encapsulation (mlKem), offered to callers to establish a ' +
      'shared secret. The package opens no connection of its own.',
    context: 'Raw keys and ciphertexts; RFC 9964 AKP JWK and seed-form PKCS#8.',
    occurrences: [
      at('src/ml-kem.js', 'ml_kem768'), at('src/seed.js', 'ml_kem768'),
      at('src/_native.node.js', "nodeName: 'ml-kem-768'"),
    ],
  },
  {
    name: 'ML-KEM-1024', scope: 'offered', primitive: 'kem', functions: KEM,
    parameterSet: '1024', oid: '2.16.840.1.101.3.4.4.3', nistLevel: 5,
    implementedBy: [NOBLE_PQ, OPENSSL], sizes: kemSizes(ml_kem1024),
    purpose: 'Category 5 key encapsulation for callers given ML-KEM-1024 as a ' +
      'requirement (mlKem1024).',
    context: 'Raw keys and ciphertexts; RFC 9964 AKP JWK and seed-form PKCS#8.',
    occurrences: [
      at('src/ml-kem-1024.js', 'ml_kem1024'), at('src/seed.js', 'ml_kem1024'),
      at('src/_native.node.js', "nodeName: 'ml-kem-1024'"),
    ],
  },
  {
    name: 'SLH-DSA-SHA2-192s', scope: 'offered', primitive: 'signature', functions: SIGN,
    parameterSet: 'SHA2-192s', oid: '2.16.840.1.101.3.4.3.22', nistLevel: 3,
    implementedBy: [NOBLE_PQ, OPENSSL], sizes: sigSizes(slh_dsa_sha2_192s),
    purpose: 'Hash-based signature (slhDsa), the hedge whose security rests on SHA-2 ' +
      'alone rather than on lattice hardness. The one SLH-DSA parameter set offered.',
    context: 'Raw keys and signatures.',
    occurrences: [
      at('src/slh-dsa.js', 'slh_dsa_sha2_192s'),
      at('src/_native.node.js', "nodeName: 'slh-dsa-sha2-192s'"),
    ],
  },
  {
    name: 'HKDF-SHA-512', scope: 'offered', primitive: 'kdf', functions: ['keyderive'],
    oid: '1.2.840.113549.1.9.16.3.30', implementedBy: [NOBLE_HASHES],
    purpose: 'Derives each keypair seed from a caller-held master secret and a ' +
      'caller-chosen info string (deriveSeed, keypairFromMaster). Zero salt; the ' +
      'master secret is the caller\'s and must be at least 16 bytes.',
    context: 'Local derivation only. Output length is the seed length of the ' +
      'parameter set being generated.',
    occurrences: [at('src/derive.js', 'hkdf'), at('src/derive.js', 'sha512')],
  },
  {
    name: 'HMAC-SHA-256', scope: 'offered', primitive: 'mac', functions: ['tag', 'verify'],
    oid: '1.2.840.113549.2.9', implementedBy: [NOBLE_HASHES],
    tagBits: 256,
    purpose: 'The shared-secret half of hybrid webhook delivery signing (webhook), ' +
      'over the same envelope as the ML-DSA signature. Verified in constant time.',
    context: 'The X-KXCO-Signature webhook header, sha256=<hex>. Key length is the ' +
      'caller\'s shared secret.',
    occurrences: [at('src/webhook.js', 'hmac'), at('src/webhook.js', 'sha256')],
  },
  {
    name: 'SHA-256', scope: 'offered', primitive: 'hash', functions: ['digest'],
    oid: '2.16.840.1.101.3.4.2.1', implementedBy: [NOBLE_HASHES],
    digestBits: 64,
    purpose: 'Key identifier (fingerprint): SHA-256 over the public key, truncated to ' +
      '16 hex characters. Identifies which key to try; it is not a security boundary ' +
      'and nothing makes a trust decision on it alone.',
    context: 'The X-KXCO-PQ-Kid webhook header and the JWS kid.',
    occurrences: [at('src/kid.js', 'sha256')],
  },

  // ── internal: executed, never offered ──────────────────────────────────────
  {
    name: 'ML-DSA-44', scope: 'internal', primitive: 'signature', functions: SIGN,
    parameterSet: '44', oid: '2.16.840.1.101.3.4.3.17', nistLevel: 2,
    implementedBy: [OPENSSL], sizes: sigSizes(ml_dsa44),
    purpose: NATIVE_PROBE + ' Also keys and signs once, with a throwaway key, to ' +
      'check that the runtime honours an ML-DSA context string.',
    context: 'In-process capability probe. Nothing leaves the process.',
    occurrences: [
      at('src/_native.node.js', "nodeName: 'ml-dsa-44'"),
      at('src/_native.node.js', "SUPPORTED.get('ML-DSA-44')"),
    ],
  },
  {
    name: 'ML-KEM-512', scope: 'internal', primitive: 'kem', functions: ['keygen'],
    parameterSet: '512', oid: '2.16.840.1.101.3.4.4.1', nistLevel: 1,
    implementedBy: [OPENSSL], sizes: kemSizes(ml_kem512),
    purpose: NATIVE_PROBE,
    context: 'In-process capability probe. Nothing leaves the process.',
    occurrences: [at('src/_native.node.js', "nodeName: 'ml-kem-512'")],
  },
  {
    name: 'SLH-DSA-SHA2-128f', scope: 'internal', primitive: 'signature', functions: ['keygen'],
    parameterSet: 'SHA2-128f', oid: '2.16.840.1.101.3.4.3.21', nistLevel: 1,
    implementedBy: [OPENSSL], sizes: sigSizes(slh_dsa_sha2_128f),
    purpose: NATIVE_PROBE,
    context: 'In-process capability probe. Nothing leaves the process.',
    occurrences: [at('src/_native.node.js', "nodeName: 'slh-dsa-sha2-128f'")],
  },
  {
    name: 'SLH-DSA-SHAKE-256f', scope: 'internal', primitive: 'signature', functions: ['keygen'],
    parameterSet: 'SHAKE-256f', oid: '2.16.840.1.101.3.4.3.31', nistLevel: 5,
    implementedBy: [OPENSSL], sizes: sigSizes(slh_dsa_shake_256f),
    purpose: NATIVE_PROBE,
    context: 'In-process capability probe. Nothing leaves the process.',
    occurrences: [at('src/_native.node.js', "nodeName: 'slh-dsa-shake-256f'")],
  },

  // ── release pipeline: classical, and stated as such ────────────────────────
  {
    name: 'ECDSA P-256', scope: 'release-pipeline', primitive: 'signature',
    functions: ['verify'], curve: 'P-256', oid: '1.2.840.10045.4.3.2',
    classicalLevel: 128, nistLevel: 0,
    purpose: 'The npm registry\'s own signature over the published tarball, checked ' +
      'by `npm audit signatures`. Registry key type ecdsa-sha2-nistp256.',
    context: 'npm registry signatures. Not performed by this package and not ' +
      'quantum-safe; the ML-DSA release signature and the reproducible build ' +
      'are the post-quantum controls beside it.',
  },
  {
    name: 'ECDSA', scope: 'release-pipeline', primitive: 'signature', functions: ['sign', 'verify'],
    nistLevel: 0,
    purpose: 'Sigstore signing of the SLSA provenance: npm provenance and ' +
      'evidence.intoto.jsonl, through the Fulcio certificate chain and the Rekor ' +
      'transparency log.',
    context: 'SLSA build provenance. Not performed by this package and not ' +
      'quantum-safe.',
  },
]

// Delivery over TLS is negotiated between the client and the host. This
// package chooses neither end, so the document names the protocol and states
// that, rather than asserting a key exchange it does not control.
export const PROTOCOLS = [
  {
    name: 'TLS', scope: 'release-pipeline', type: 'tls',
    purpose: 'Transport that delivers the package from the npm registry and the ' +
      'release assets from GitHub.',
    context: 'Key exchange is negotiated per connection by the client and the host; ' +
      'this package does not choose it and makes no quantum-safety claim for it. ' +
      'The ML-DSA release signature, with its public key committed to the ' +
      'repository, is the control that does not depend on the transport.',
  },
]

// ── checking the declaration against the source ────────────────────────────

// node:crypto functions whose algorithm is fixed by a key that came from the
// native algorithm table. Anything else on `crypto.` names an algorithm of its
// own (createHash, createHmac, randomBytes, subtle...) and must be declared.
const KEY_BOUND = new Set([
  'generateKeyPairSync', 'sign', 'verify', 'createPrivateKey', 'createPublicKey',
  'encapsulate', 'decapsulate',
])

// Whole-line and block comments only. Enough for this codebase, which puts
// comments on their own lines, and it keeps a use mentioned in prose from
// counting as a use in code.
export function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ''))
    .split('\n')
    .map((line) => (/^\s*\/\//.test(line) ? '' : line))
    .join('\n')
}

/**
 * Every place the source binds an algorithm.
 * @param {{ location: string, text: string }[]} files
 * @returns {{ location: string, symbol: string }[]}
 */
export function detect(files) {
  const found = []
  for (const { location, text } of files) {
    const code = stripComments(text)
    for (const m of code.matchAll(/import\s*\{([^}]*)\}\s*from\s*'(@noble\/[^']+)'/g)) {
      for (const name of m[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
        found.push({ location, symbol: name })
      }
    }
    for (const m of code.matchAll(/nodeName: '([a-z0-9-]+)'/g)) {
      found.push({ location, symbol: `nodeName: '${m[1]}'` })
    }
    for (const m of code.matchAll(/\bcrypto\.(\w+)\s*\(([^)]*)/g)) {
      const [, fn, firstArg] = m
      if (!KEY_BOUND.has(fn)) { found.push({ location, symbol: `crypto.${fn}` }); continue }
      // The key-bound calls are only key-bound when they are used that way: a
      // generateKeyPairSync('rsa') or a sign('sha256', ...) names its own algorithm.
      const arg = firstArg.split(',')[0].trim()
      if (fn === 'generateKeyPairSync' && !/^(spec\.)?nodeName$/.test(arg)) {
        found.push({ location, symbol: `crypto.generateKeyPairSync(${arg})` })
      }
      if ((fn === 'sign' || fn === 'verify') && arg !== 'null') {
        found.push({ location, symbol: `crypto.${fn}(${arg})` })
      }
    }
    if (/\bsubtle\s*\./.test(code)) found.push({ location, symbol: 'crypto.subtle' })
  }
  return found
}

export function readSources(root = ROOT) {
  const files = readdirSync(join(root, 'src'))
    .filter((f) => f.endsWith('.js'))
    .map((f) => 'src/' + f)
  files.push('scripts/sign-release.mjs')
  return files.map((location) => ({ location, text: readFileSync(join(root, location), 'utf8') }))
}

/**
 * Throws unless the declaration and the source agree in both directions.
 * Returns each declared occurrence with the line it was found on.
 */
export function reconcile(assets, files) {
  const byLocation = new Map(files.map((f) => [f.location, stripComments(f.text).split('\n')]))
  const declared = new Set()
  const stale = []
  const lines = new Map()
  for (const a of assets) {
    for (const o of a.occurrences ?? []) {
      declared.add(o.location + '\0' + o.symbol)
      const src = byLocation.get(o.location)
      const i = src ? src.findIndex((l) => l.includes(o.symbol)) : -1
      if (i === -1) stale.push(`${a.name}: ${o.symbol} in ${o.location}`)
      else lines.set(o.location + '\0' + o.symbol, i + 1)
    }
  }
  const undeclared = detect(files)
    .filter((d) => !declared.has(d.location + '\0' + d.symbol))
    .map((d) => `${d.symbol} in ${d.location}`)
  const problems = [
    ...undeclared.map((u) => 'undeclared cryptography: ' + u),
    ...stale.map((s) => 'declared but not in the source: ' + s),
  ]
  if (problems.length) {
    throw new Error('the CBOM does not match the source:\n  ' + problems.join('\n  '))
  }
  return lines
}

// ── the document ───────────────────────────────────────────────────────────

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
const algRef = (name) => 'crypto/algorithm/' + slug(name)

function purl(name, version) {
  const encoded = name.startsWith('@') ? '%40' + name.slice(1) : encodeURIComponent(name)
  return 'pkg:npm/' + encoded + '@' + version
}

function lockedVersion(root, name) {
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'))
  const entry = lock.packages['node_modules/' + name]
  if (!entry) throw new Error(`${name} is not in package-lock.json`)
  return entry.version
}

function sourceDate(root) {
  const epoch = process.env.SOURCE_DATE_EPOCH
  if (epoch && /^\d+$/.test(epoch)) return new Date(Number(epoch) * 1000)
  try {
    const ct = execFileSync('git', ['log', '-1', '--format=%ct'], { cwd: root, encoding: 'utf8' }).trim()
    if (/^\d+$/.test(ct)) return new Date(Number(ct) * 1000)
  } catch {}
  return null
}

const prop = (name, value) => ({ name: 'kxco:' + name, value: String(value) })

function algorithmComponent(a, lines) {
  const ref = algRef(a.name)
  const inLibrary = a.scope !== 'release-pipeline'
  const properties = [
    prop('scope', a.scope),
    prop('context', a.context),
    ...(a.implementedBy ?? []).map((i) => prop('implementedBy', i === OPENSSL
      ? 'OpenSSL 3.5+ in the host runtime (native backend, Node 24+)'
      : i)),
    ...(a.digestBits ? [prop('outputBits', a.digestBits)] : []),
    ...(a.tagBits ? [prop('tagBits', a.tagBits)] : []),
  ]
  const occurrences = (a.occurrences ?? []).map((o) => ({
    location: o.location,
    line: lines.get(o.location + '\0' + o.symbol),
    symbol: o.symbol,
  }))
  return {
    type: 'cryptographic-asset',
    'bom-ref': ref,
    name: a.name,
    description: a.purpose,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: a.primitive,
        ...(a.parameterSet ? { parameterSetIdentifier: a.parameterSet } : {}),
        ...(a.curve ? { curve: a.curve } : {}),
        ...(inLibrary ? { executionEnvironment: 'software-plain-ram', implementationPlatform: 'generic' } : {}),
        // No FIPS 140 validated module carries this package. Stated rather than
        // left blank, because a consumer reads blank as unknown.
        ...(inLibrary ? { certificationLevel: ['none'] } : {}),
        cryptoFunctions: a.functions,
        ...(a.classicalLevel !== undefined ? { classicalSecurityLevel: a.classicalLevel } : {}),
        ...(a.nistLevel !== undefined ? { nistQuantumSecurityLevel: a.nistLevel } : {}),
      },
      ...(a.oid ? { oid: a.oid } : {}),
    },
    properties,
    ...(occurrences.length ? { evidence: { occurrences } } : {}),
  }
}

// One component per key, signature, ciphertext, shared secret and seed, each
// with its size in bits. This is the per-field form of "key sizes": a consumer
// reads `size` on a public key rather than inferring it from a parameter set.
function materialComponents(a) {
  if (!a.sizes) return []
  return Object.entries(a.sizes).map(([type, bytes]) => ({
    type: 'cryptographic-asset',
    'bom-ref': `crypto/material/${slug(a.name)}/${type}`,
    name: `${a.name} ${type.replace('-', ' ')}`,
    cryptoProperties: {
      assetType: 'related-crypto-material',
      relatedCryptoMaterialProperties: {
        type,
        algorithmRef: algRef(a.name),
        size: bytes * 8,
        format: 'raw',
      },
    },
    properties: [prop('sizeBytes', bytes)],
  }))
}

function protocolComponent(p) {
  return {
    type: 'cryptographic-asset',
    'bom-ref': 'crypto/protocol/' + slug(p.name),
    name: p.name,
    description: p.purpose,
    cryptoProperties: { assetType: 'protocol', protocolProperties: { type: p.type } },
    properties: [prop('scope', p.scope), prop('context', p.context)],
  }
}

/**
 * @param {{ root?: string, assets?: object[], files?: {location: string, text: string}[] }} [opts]
 */
export function buildCbom(opts = {}) {
  const root = opts.root ?? ROOT
  const assets = opts.assets ?? ASSETS
  const files = opts.files ?? readSources(root)
  const lines = reconcile(assets, files)

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  const self = purl(pkg.name, pkg.version)
  const libs = [NOBLE_PQ, NOBLE_HASHES].map((name) => ({ name, version: lockedVersion(root, name) }))
  const libRef = Object.fromEntries(libs.map((l) => [l.name, purl(l.name, l.version)]))
  const opensslRef = 'runtime/openssl'

  const components = [
    ...libs.map((l) => ({
      type: 'library', 'bom-ref': libRef[l.name], name: l.name, version: l.version, purl: libRef[l.name],
    })),
    {
      type: 'library', 'bom-ref': opensslRef, name: 'OpenSSL',
      description: 'The host runtime\'s OpenSSL 3.5 or later, used as the native backend ' +
        'on Node 24 and later. Not bundled; its version is the host\'s.',
    },
    ...assets.flatMap((a) => [algorithmComponent(a, lines), ...materialComponents(a)]),
    ...PROTOCOLS.map(protocolComponent),
  ]

  const providers = { [NOBLE_PQ]: [], [NOBLE_HASHES]: [], [OPENSSL]: [] }
  for (const a of assets) for (const i of a.implementedBy ?? []) providers[i].push(algRef(a.name))
  const inLibrary = assets.filter((a) => a.scope !== 'release-pipeline').map((a) => algRef(a.name))

  const dependencies = [
    { ref: self, dependsOn: [...Object.values(libRef), opensslRef].sort(), provides: inLibrary.sort() },
    ...libs.map((l) => ({ ref: libRef[l.name], provides: providers[l.name].sort() })),
    { ref: opensslRef, provides: providers[OPENSSL].sort() },
  ]

  const date = sourceDate(root)
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      ...(date ? { timestamp: date.toISOString().replace(/\.\d{3}Z$/, 'Z') } : {}),
      tools: { components: [{ type: 'application', name: 'kxco-post-quantum build-cbom', version: pkg.version }] },
      component: { type: 'library', 'bom-ref': self, name: pkg.name, version: pkg.version, purl: self },
      properties: [
        prop('cbom:method', 'Declared in scripts/build-cbom.mjs and reconciled against the ' +
          'source on every build: the build fails if src/ binds an algorithm not declared ' +
          'here, or if a declared use is no longer in the source.'),
        prop('cbom:scopes', 'offered = public API; internal = executed by the package but ' +
          'not offered; release-pipeline = how the package reaches a user, not performed ' +
          'by the library.'),
      ],
    },
    components,
    dependencies,
  }
  const serial = createHash('sha1')
    .update(Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex'))
    .update(JSON.stringify(doc))
    .digest()
  serial[6] = (serial[6] & 0x0f) | 0x50
  serial[8] = (serial[8] & 0x3f) | 0x80
  const h = serial.subarray(0, 16).toString('hex')
  return {
    bomFormat: doc.bomFormat,
    specVersion: doc.specVersion,
    serialNumber: `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`,
    ...doc,
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2)
  const out = args.includes('--out') ? args[args.indexOf('--out') + 1] : null
  const json = JSON.stringify(buildCbom(), null, 2) + '\n'
  if (out) writeFileSync(out, json)
  else process.stdout.write(json)
}
