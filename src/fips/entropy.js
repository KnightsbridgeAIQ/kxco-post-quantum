// The FIPS module's entropy source: the operating system's random device,
// read directly.
//
// The source sits outside the module's boundary. Under FIPS 140-3 IG 9.3.A case
// 1(c) a module whose approved DRBG requests entropy from outside its boundary
// is validated with the caveat "No assurance of the minimum strength of
// generated SSPs (e.g., keys)", provided the module fixes the minimum it asks
// for and its Security Policy states it. module.js fixes the amounts.
//
// This deliberately does not use crypto.getRandomValues or crypto.randomBytes:
// in Node both are OpenSSL's RAND_bytes, which is another DRBG rather than the
// kernel's source. On Linux the device is the kernel's CSPRNG. Where the device
// does not exist (Windows) the module cannot obtain entropy and stays in its
// error state.

import { openSync, readSync, closeSync } from 'node:fs'

const DEVICE = '/dev/urandom'

export function getEntropy(length) {
  const out = new Uint8Array(length)
  const fd = openSync(DEVICE, 'r')
  try {
    let filled = 0
    while (filled < length) {
      const n = readSync(fd, out, filled, length - filled, null)
      if (n <= 0) throw new Error(`entropy source ${DEVICE} returned no data`)
      filled += n
    }
  } finally {
    closeSync(fd)
  }
  return out
}
