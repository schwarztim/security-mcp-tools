import crypto from 'crypto';

/**
 * BloodHound CE HMAC Authentication
 *
 * Implements signed request authentication as recommended by SpecterOps.
 * The signature is computed using HMAC-SHA256 with a chained digest:
 * 1. OperationKey = HMAC(tokenKey, method + uri)
 * 2. DateKey = HMAC(operationKey, datetime)
 * 3. Signature = HMAC(dateKey, body)
 */

export interface BloodHoundAuth {
  tokenId: string;
  tokenKey: string;
}

export interface SignedHeaders {
  Authorization: string;
  RequestDate: string;
  Signature: string;
  'Content-Type': string;
}

/**
 * Generate RFC3339 datetime string (to the hour for replay attack prevention)
 */
function getRequestDate(): string {
  const now = new Date();
  // Round to the hour as per BloodHound spec
  now.setMinutes(0, 0, 0);
  return now.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Compute HMAC-SHA256 digest
 */
function hmacDigest(key: Buffer | string, data: string): Buffer {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest();
}

/**
 * Generate signed request headers for BloodHound API
 */
export function signRequest(
  auth: BloodHoundAuth,
  method: string,
  uri: string,
  body: string = ''
): SignedHeaders {
  const requestDate = getRequestDate();

  // Chain HMAC digests
  // 1. Operation key: prevents method/URI modification
  const operationKey = hmacDigest(auth.tokenKey, `${method.toUpperCase()}${uri}`);

  // 2. Date key: prevents replay attacks
  const dateKey = hmacDigest(operationKey, requestDate);

  // 3. Body signature: prevents payload tampering
  const signature = hmacDigest(dateKey, body);
  const base64Signature = signature.toString('base64');

  return {
    Authorization: `bhesignature ${auth.tokenId}`,
    RequestDate: requestDate,
    Signature: base64Signature,
    'Content-Type': 'application/json'
  };
}

/**
 * Validate authentication configuration
 */
export function validateAuth(auth: BloodHoundAuth): boolean {
  return !!(auth.tokenId && auth.tokenKey);
}
