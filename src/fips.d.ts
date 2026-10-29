/** Parameter sets kxco-post-quantum/fips offers. */
export type FipsAlgorithm = 'ML-KEM-768' | 'ML-KEM-1024' | 'ML-DSA-65' | 'ML-DSA-87'
export type FipsKemAlgorithm = 'ML-KEM-768' | 'ML-KEM-1024'
export type FipsDsaAlgorithm = 'ML-DSA-65' | 'ML-DSA-87'

export interface FipsStatus {
  module: 'kxco-post-quantum/fips'
  /** The package version recorded in the signed manifest, or null if the integrity test did not pass. */
  version: string | null
  state: 'operational' | 'error'
  /** Why the module is in the error state. */
  reason?: string
  /** The entropy caveat, FIPS 140-3 IG 9.3.A. */
  caveat: string
  algorithms: readonly FipsAlgorithm[]
}

export const MODULE_NAME: 'kxco-post-quantum/fips'
export const CAVEAT: string
export const ALGORITHMS: readonly FipsAlgorithm[]

export function status(): FipsStatus
/** Runs the integrity test and every algorithm self-test again. Throws ERR_KXCO_PQ_FIPS and enters the error state on failure. */
export function selfTest(): FipsStatus

/** A new key pair from a seed drawn from the module's DRBG, after a pairwise consistency test. Store `seed`; it is the key. */
export function generateKeypair(alg: FipsAlgorithm): { alg: FipsAlgorithm; publicKey: Uint8Array; secretKey: Uint8Array; seed: Uint8Array }
/** Re-expand a stored seed: 64 bytes for ML-KEM, 32 for ML-DSA. */
export function keypairFromSeed(alg: FipsAlgorithm, seed: Uint8Array): { alg: FipsAlgorithm; publicKey: Uint8Array; secretKey: Uint8Array }

export function encapsulate(alg: FipsKemAlgorithm, publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array }
export function decapsulate(alg: FipsKemAlgorithm, cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array

export function sign(alg: FipsDsaAlgorithm, secretKey: Uint8Array, message: Uint8Array | string, opts?: { context?: Uint8Array | string }): Uint8Array
export function verify(alg: FipsDsaAlgorithm, publicKey: Uint8Array, message: Uint8Array | string, signature: Uint8Array, opts?: { context?: Uint8Array | string }): boolean

/** Overwrite the given buffers with zeros. Available in every state. */
export function zeroize(...arrays: Uint8Array[]): void
