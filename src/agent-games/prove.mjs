// Local Groth16 proving for the Gatekeeper circuit (snarkjs, BN128).
//
// Circuit inputs (13, verified against the official wasm — the witness
// calculation fails if any name is wrong, and the local verification
// below passes only for the exact mapping):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision ("1" = APPROVE, "0" = REJECT), taskId, salt (private).
// Public signals (13, snarkjs output-then-public order):
//   [hash, registeredVkHash, proofVkHash, minimum, publicBalance,
//    expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//    maxTransfer, decision, taskId]
// The first signal is a salt-dependent binding hash the platform cannot
// recompute; signals [1..12] echo the task fields, which the platform
// checks against the envelope.
//
// taskId mapping: the envelope task_id is a string (e.g. "gk_24_9d1").
// The circuit needs a field element. Default: keccak256(task_id UTF-8)
// mod FIELD_PRIME. This is the mapping both participant implementations
// use; if a practice proof is rejected by the platform, the other
// candidates are "numeric" (digits of the suffix) and "hex" (hex chars
// of the suffix) — switchable via GATEKEEPER_TASK_ID_MODE without
// touching any other code.
import * as snarkjs from 'snarkjs';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toFieldString } from './field.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ASSETS = join(HERE, '..', '..', 'assets', 'agent-games');
export const GATEKEEPER_WASM = join(ASSETS, 'gatekeeper.wasm');
export const GATEKEEPER_ZKEY = join(ASSETS, 'gatekeeper_final.zkey');

let vkCache = null;
export async function getVerificationKey() {
  if (!vkCache) {
    try {
      vkCache = JSON.parse(readFileSync(join(ASSETS, 'gatekeeper_vk.json'), 'utf8'));
    } catch {
      // Fall back to exporting from the zkey (e.g. fresh checkout where
      // the build step has not run yet).
      vkCache = await snarkjs.zKey.exportVerificationKey(GATEKEEPER_ZKEY);
    }
  }
  return vkCache;
}

export async function verifyLocally(publicSignals, proof) {
  const vk = await getVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

export function taskIdToField(taskId, mode = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak') {
  const id = String(taskId ?? '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toFieldString(BigInt(digits)) : '0';
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toFieldString(BigInt('0x' + hex)) : '0';
  }
  return toFieldString(id); // keccak256(utf8) mod p for non-numeric strings
}

export function buildCircuitInput(envelopeInput, taskId, decision) {
  const salt = (BigInt('0x' + randomBytes(32).toString('hex')) %
    21888242871839275222246405745257275088548364400416034343698204186575808495617n).toString();
  return {
    registeredVkHash: toFieldString(envelopeInput.registered_vk ?? 0),
    proofVkHash: toFieldString(envelopeInput.proof_vk ?? 0),
    minimum: String(envelopeInput.minimum ?? 0),
    publicBalance: String(envelopeInput.public_balance ?? 0),
    expiryBlock: String(envelopeInput.expiry_block ?? 0),
    currentBlock: String(envelopeInput.current_block ?? 0),
    recipient: toFieldString(envelopeInput.recipient ?? 0),
    conditionRecipient: toFieldString(envelopeInput.condition_recipient ?? 0),
    amount: String(envelopeInput.amount ?? 0),
    maxTransfer: String(envelopeInput.max_transfer ?? 0),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(taskId),
    salt,
  };
}

// Generate the proof. Throws if the witness calculation fails — that means
// the inputs violate the circuit (e.g. a decision that does not match the
// circuit's own evaluation). Callers must fail closed on throw.
export async function proveGatekeeper(envelopeInput, taskId, decision) {
  const input = buildCircuitInput(envelopeInput, taskId, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, GATEKEEPER_WASM, GATEKEEPER_ZKEY);
  return { proof, publicSignals };
}

export { createHash };
