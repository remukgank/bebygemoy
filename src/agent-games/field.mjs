// Field-element helpers for the BN128 (alt_bn128) scalar field — the field
// of both Agent Games circuits (Circom 2.x / Groth16 / snarkjs).
// Values are converted to decimal strings in [0, p).
import { createHash } from 'node:crypto';

export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// x: hex string (0x..), decimal string, number, or BigInt -> field element (BigInt, mod p).
export function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else {
    const s = String(x).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) b = BigInt(s);
    else if (/^\d+$/.test(s)) b = BigInt(s);
    else b = BigInt('0x' + createHash('sha3-256').update(Buffer.from(s, 'utf8')).digest('hex'));
  }
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

export function toFieldString(x) {
  return toField(x).toString();
}

// keccak256 (UTF-8 string) mod p — the default taskId mapping used by the
// participant implementations and the one this agent uses (see prove.mjs).
export function taskIdToField(taskId) {
  return toFieldString(String(taskId ?? ''));
}
