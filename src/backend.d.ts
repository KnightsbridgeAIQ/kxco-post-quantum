export interface BackendReport {
  kind: 'openssl' | 'javascript'
  library: string
  /** OpenSSL version, on the native backend only. */
  openssl?: string
  /** Parameter sets the native backend can express. */
  parameterSets?: string[]
  /** Why the native backend is unavailable, on the JavaScript backend only. */
  reason?: string
  /** The operator's KXCO_PQ_BACKEND pin, when one is set. */
  pinned?: 'openssl' | 'javascript'
}

/** Describe the backend doing the maths in this process. Reports; never switches. */
export function backend(): BackendReport

/** Whether a parameter set runs natively here, e.g. isNative('ML-DSA-65'). */
export function isNative(alg: string): boolean

/**
 * Refuse to run unless the cryptography is executing in the native backend.
 *
 * An assertion, not a switch: it cannot change which implementation signs, it
 * stops a process that has silently landed on the JavaScript backend when the
 * operator required otherwise. Also settable from the environment with
 * `KXCO_PQ_REQUIRE_NATIVE=1`, which applies the check at import.
 *
 * Asserts that OpenSSL is doing the maths. Whether that OpenSSL is a
 * FIPS-validated module is a property of the operator's build and is not
 * visible from here.
 *
 * @param algorithms Parameter sets that must run natively. Omit to require
 *   only that the native backend is present.
 * @throws Error with `code: 'ERR_KXCO_PQ_BACKEND'` when the requirement fails.
 */
export function requireNativeBackend(algorithms?: string[]): BackendReport

/**
 * Refuse to run unless the cryptography is executing in a named implementation.
 *
 * The general form of requireNativeBackend. Both implementations are being
 * taken to algorithm validation, so a deployment under a control that names a
 * certificate must be able to pin the one its certificate covers, and for some
 * that is the JavaScript one.
 *
 * Asserting 'javascript' where OpenSSL is present fails unless the operator
 * also set `KXCO_PQ_BACKEND=javascript`. This function reports; the
 * environment decides. Keeping those apart is what stops application code
 * quietly changing which implementation a customer's evidence is about.
 *
 * @param kind Which implementation must be running.
 * @param algorithms Parameter sets that must run in it. Only meaningful for
 *   'openssl'; the JavaScript backend covers every set.
 * @throws Error with `code: 'ERR_KXCO_PQ_BACKEND'` when the requirement fails.
 */
export function requireBackend(
  kind: 'openssl' | 'javascript',
  algorithms?: string[],
): BackendReport
