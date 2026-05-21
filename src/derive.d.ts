/// <reference types="node" />

/**
 * Derive a deterministic seed from a master secret + an info string,
 * using HKDF-SHA-512 with an empty salt.
 *
 * Same `master + info + length` always produces the same seed.
 *
 * @param master — high-entropy input keying material (≥16 bytes)
 * @param info   — domain separation tag (eg. 'kxco-platform-ml-dsa-65-v1')
 * @param length — output seed length in bytes (32 for ML-DSA, 64 for ML-KEM)
 *
 * @throws {Error} if `master` is shorter than 16 bytes
 * @throws {Error} if `info` is empty or not a string
 */
export function deriveSeed(
  master: Buffer | Uint8Array,
  info:   string,
  length: number,
): Buffer
