// HMAC-SHA256 helpers for the Agent Games protocol (rules 1.2-1.3).
// The platform signs every inbound request with x-agent-games-signature =
// HMAC-SHA256(secret, RAW request body). Our responses must be signed the
// same way over the raw response body. Verification happens BEFORE any
// JSON parsing, and uses a timing-safe comparison. Fail closed: any
// missing/mismatched signature -> 401, never process the task.
import { createHmac, timingSafeEqual } from 'node:crypto';

export function hmacHex(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  return createHmac('sha256', secret).update(body).digest('hex');
}

// Returns true only when the presented signature matches the HMAC of the
// raw body. Accepts hex signatures with or without a 0x prefix, any case.
export function verifyHmac(secret, rawBody, presented) {
  if (!secret || typeof presented !== 'string') return false;
  const clean = presented.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(clean)) return false;
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(clean, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function signResponse(secret, rawBody) {
  return hmacHex(secret, rawBody);
}
