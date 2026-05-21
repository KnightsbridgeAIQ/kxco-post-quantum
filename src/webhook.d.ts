/// <reference types="node" />

/**
 * Build the canonical signed envelope: `timestamp + "." + raw_body`.
 *
 * Receivers MUST construct the envelope from the timestamp header and the
 * RAW request body bytes as received. Re-serialising a parsed JSON object
 * will not produce the same bytes and signature verification will fail.
 */
export function envelope(
  timestamp: string | number,
  rawBody:   string | Buffer,
): Buffer

/**
 * Compute the hex HMAC-SHA-256 of the envelope using the shared secret.
 * Returns the hex value WITHOUT the `sha256=` prefix.
 */
export function hmacHex(
  secret:    string | Buffer,
  timestamp: string | number,
  rawBody:   string | Buffer,
): string

/**
 * Constant-time verify of the X-KXCO-Signature header.
 * Accepts the header value with or without the `sha256=` prefix.
 */
export function verifyHmac(
  secret:    string | Buffer,
  timestamp: string | number,
  rawBody:   string | Buffer,
  sigHeader: string,
): boolean

/**
 * Produce the X-KXCO-PQ-Signature header value: the hex ML-DSA-65
 * signature over the envelope, prefixed with `ml-dsa-65=`.
 */
export function pqSign(
  secretKey: Buffer | Uint8Array,
  timestamp: string | number,
  rawBody:   string | Buffer,
): string

/**
 * Verify a hex ML-DSA-65 signature header.
 * Accepts the value with or without the `ml-dsa-65=` prefix.
 */
export function verifyPq(
  publicKey: Buffer | Uint8Array,
  timestamp: string | number,
  rawBody:   string | Buffer,
  sigHeader: string,
): boolean

export interface SignDeliveryArgs {
  /** The exact body bytes that will be transmitted */
  rawBody:     string | Buffer
  /** Per-endpoint shared secret for HMAC */
  hmacSecret:  string | Buffer
  /** Raw ML-DSA-65 secret key */
  pqSecretKey: Buffer | Uint8Array
  /** 16-hex kid fingerprint of the matching public key */
  pqKid:       string
  /** Optional event name (eg. "payment.settled") */
  event?:      string
  /** Optional delivery / idempotency identifier */
  deliveryId?: string
}

export interface SignDeliveryHeaders {
  'Content-Type':         'application/json'
  'X-KXCO-Timestamp':     string
  'X-KXCO-Signature':     string   // sha256=<hex>
  'X-KXCO-PQ-Signature':  string   // ml-dsa-65=<hex>
  'X-KXCO-PQ-Kid':        string
  'X-KXCO-Event'?:        string
  'X-KXCO-Delivery'?:     string
}

/**
 * Sign a webhook delivery. Returns the full set of headers a sender
 * should attach to the HTTP request.
 *
 * The caller is responsible for sending `rawBody` byte-for-byte
 * unchanged. The receiver verifies against the bytes as transmitted.
 */
export function signDelivery(args: SignDeliveryArgs): SignDeliveryHeaders

export interface VerifyDeliveryArgs {
  /** HTTP headers with LOWERCASE keys */
  headers: Record<string, string | undefined>
  /** The EXACT request body bytes as received */
  rawBody: string | Buffer
  /** Optional: enable HMAC verification by providing the shared secret */
  hmacSecret?: string | Buffer
  /** Optional: enable PQ verification by providing the platform public key */
  pqPublicKey?: Buffer | Uint8Array
  /** Required when `pqPublicKey` is provided */
  pinnedKid?: string
  /** Replay-window in seconds. Default 300 (5 minutes). */
  windowSeconds?: number
}

export interface VerifyDeliveryResult {
  hmacOk:      boolean
  pqOk:        boolean
  timestampOk: boolean
  kidOk:       boolean
}

/**
 * Verify a webhook delivery on the receiving side.
 *
 * Returns a breakdown of which predicates passed. A delivery is
 * acceptable when `(hmacOk || pqOk) && timestampOk && kidOk`.
 */
export function verifyDelivery(args: VerifyDeliveryArgs): VerifyDeliveryResult
