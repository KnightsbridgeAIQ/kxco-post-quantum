// @kxco/post-quantum
//
// Production-tested post-quantum cryptography patterns: deterministic key
// derivation, hybrid HMAC + ML-DSA webhook signing, kid fingerprinting.
// Built on @noble/post-quantum. Used in production at KXCO across
// KnightsVault, KXCO Bank, KnightsBot, The Exchequer, and Armature L1.
//
// This package does NOT reimplement the NIST primitives. It wraps the
// audited @noble/post-quantum reference implementation with the integration
// patterns we have proven in production.

export * as mlDsa  from './ml-dsa.js'
export * as mlKem  from './ml-kem.js'
export * from './derive.js'
export * from './kid.js'
export * as webhook from './webhook.js'
