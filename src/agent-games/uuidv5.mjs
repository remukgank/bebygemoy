// Deterministic UUID v5 (RFC 4122, SHA-1) — no extra dependency.
// Ported from the Realgood-2 reference (src/uuidv5.ts, TypeScript).
//
// Why: the Steal track's `idempotencyKey` must be a UUID. The platform
// validates the response schema and rejects anything else — a practice
// dispatch failed with "idempotencyKey: Invalid UUID" when the key was
// the plain string `steal-<matchId>-turn-<n>`. UUID v5 keeps the key
// deterministic per turn (a platform retry after a network failure
// receives the identical response) while satisfying the schema. The
// namespace is the RFC 4122 URL namespace.
import { createHash } from 'node:crypto';

export const STEAL_IDEMPOTENCY_NAMESPACE = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

export function uuidv5(namespace, name) {
  const ns = String(namespace).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(ns)) {
    throw new Error('uuidv5: invalid namespace UUID');
  }
  const nsBytes = Buffer.from(ns, 'hex');
  const hash = createHash('sha1').update(nsBytes).update(name, 'utf8').digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // variant RFC 4122
  const hex = b.toString('hex');
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

/** Deterministic UUID v5 idempotency key for one Steal turn. */
export function stealIdempotencyKey(matchId, turn) {
  return uuidv5(STEAL_IDEMPOTENCY_NAMESPACE, `steal:${matchId}:turn:${turn}`);
}
