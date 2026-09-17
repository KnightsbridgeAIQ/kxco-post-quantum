// What we tell NIST we can do.
//
// A registration is a claim. Claim a capability the backend refuses and the
// session fails, which is the correct outcome and an expensive way to learn it.
// So the pre-hash lists here are DERIVED from the same security-strength rule
// the backend enforces, rather than copied from NIST's example registration,
// which pairs every hash with every parameter set.
//
// The rule: the JavaScript backend refuses a pre-hash whose collision strength
// is below the parameter set's security category. That is the backend's policy,
// not a FIPS 204 or FIPS 205 requirement, and it is why our HashML-DSA claim is
// narrower than the full matrix. Stating the narrow claim is the honest move.

const HASH_STRENGTH = {
  'SHA2-224': 112,
  'SHA2-256': 128,
  'SHA2-384': 192,
  'SHA2-512': 256,
  'SHA2-512/224': 112,
  'SHA2-512/256': 128,
  'SHA3-224': 112,
  'SHA3-256': 128,
  'SHA3-384': 192,
  'SHA3-512': 256,
  // The pre-hash variants fix the XOF output length: SHAKE128 at 256 bits,
  // SHAKE256 at 512 bits, giving 128 and 256 bits of collision resistance.
  'SHAKE-128': 128,
  'SHAKE-256': 256,
}

const REQUIRED = {
  'ML-DSA-44': 128,
  'ML-DSA-65': 192,
  'ML-DSA-87': 256,
  'SLH-DSA-SHA2-128s': 128,
  'SLH-DSA-SHA2-128f': 128,
  'SLH-DSA-SHA2-192s': 192,
  'SLH-DSA-SHA2-192f': 192,
  'SLH-DSA-SHA2-256s': 256,
  'SLH-DSA-SHA2-256f': 256,
  'SLH-DSA-SHAKE-128s': 128,
  'SLH-DSA-SHAKE-128f': 128,
  'SLH-DSA-SHAKE-192s': 192,
  'SLH-DSA-SHAKE-192f': 192,
  'SLH-DSA-SHAKE-256s': 256,
  'SLH-DSA-SHAKE-256f': 256,
}

export function hashesFor(parameterSet) {
  const floor = REQUIRED[parameterSet]
  return Object.entries(HASH_STRENGTH)
    .filter(([, strength]) => strength >= floor)
    .map(([name]) => name)
}

// One capability entry per parameter set, so each carries only the pre-hashes
// that parameter set can actually take.
const byParameterSet = (sets, extra = {}) =>
  sets.map((ps) => ({ parameterSets: [ps], hashAlgs: hashesFor(ps), ...extra }))

const ML_KEM = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']
const ML_DSA = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
const SLH_DSA = Object.keys(REQUIRED).filter((k) => k.startsWith('SLH-DSA'))

export const REGISTRATIONS = {
  'ml-kem-keygen': {
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    parameterSets: ML_KEM,
  },

  'ml-kem-encapdecap': {
    algorithm: 'ML-KEM',
    mode: 'encapDecap',
    revision: 'FIPS203',
    parameterSets: ML_KEM,
    functions: ['encapsulation', 'decapsulation', 'encapsulationKeyCheck', 'decapsulationKeyCheck'],
  },

  'ml-dsa-keygen': {
    algorithm: 'ML-DSA',
    mode: 'keyGen',
    revision: 'FIPS204',
    parameterSets: ML_DSA,
  },

  'ml-dsa-siggen': {
    algorithm: 'ML-DSA',
    mode: 'sigGen',
    revision: 'FIPS204',
    capabilities: byParameterSet(ML_DSA, {
      messageLength: [{ min: 8, max: 65536, increment: 8 }],
      contextLength: [{ min: 0, max: 2040, increment: 8 }],
    }),
    deterministic: [true, false],
    externalMu: [true, false],
    signatureInterfaces: ['external', 'internal'],
    preHash: ['pure', 'preHash'],
  },

  'ml-dsa-sigver': {
    algorithm: 'ML-DSA',
    mode: 'sigVer',
    revision: 'FIPS204',
    capabilities: byParameterSet(ML_DSA, {
      messageLength: [{ min: 8, max: 65536, increment: 8 }],
      contextLength: [{ min: 0, max: 2040, increment: 8 }],
    }),
    externalMu: [true, false],
    signatureInterfaces: ['external', 'internal'],
    preHash: ['pure', 'preHash'],
  },

  'slh-dsa-keygen': {
    algorithm: 'SLH-DSA',
    mode: 'keyGen',
    revision: 'FIPS205',
    parameterSets: SLH_DSA,
  },

  'slh-dsa-siggen': {
    algorithm: 'SLH-DSA',
    mode: 'sigGen',
    revision: 'FIPS205',
    capabilities: byParameterSet(SLH_DSA, {
      messageLength: [{ min: 8, max: 65536, increment: 8 }],
      contextLength: [{ min: 0, max: 2040, increment: 8 }],
    }),
    deterministic: [true, false],
    signatureInterfaces: ['external', 'internal'],
    preHash: ['pure', 'preHash'],
  },

  'slh-dsa-sigver': {
    algorithm: 'SLH-DSA',
    mode: 'sigVer',
    revision: 'FIPS205',
    capabilities: byParameterSet(SLH_DSA, {
      messageLength: [{ min: 8, max: 65536, increment: 8 }],
      contextLength: [{ min: 0, max: 2040, increment: 8 }],
    }),
    signatureInterfaces: ['external', 'internal'],
    preHash: ['pure', 'preHash'],
  },
}
