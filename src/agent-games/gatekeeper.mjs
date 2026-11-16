// Proof Gatekeeper — deterministic decision logic (no LLM, no guessing).
//
// The gatekeeper circuit itself is the referee: it constrains the decision
// bit to the correct evaluation of the 12 task fields, so a wrong decision
// fails witness generation. This module must therefore implement EXACTLY
// the circuit's checks (verified by probing the official wasm — see
// scripts/probe-circuit.mjs and docs/endpoints.md §6):
//   - public_balance == minimum is VALID (threshold inclusive)
//   - current_block == expiry_block is EXPIRED (STRICT: valid only while
//     current_block < expiry_block) — this corrects the plan §2.3 text,
//     which wrote `>`; both participant implementations and the circuit
//     probe use `>=`.
//   - amount == max_transfer is VALID (max inclusive)
//   - proof_tx reuse is tracked per task_id: a platform retry of the SAME
//     task_id is NOT a reuse; the same proof_tx under another task_id IS.
//
// Check order (first failing trap wins; reason_code = trap name):
//   VK_SUBSTITUTION -> PROOF_REUSED -> THRESHOLD_MISMATCH ->
//   EXPIRED_CONDITION -> RECIPIENT_MISMATCH -> AMOUNT_OVERFLOW
//   else VALID_CONDITION -> APPROVE.
// When in doubt, REJECT (fail closed): APPROVE-wrong costs -6, REJECT-wrong -3.
//
// PROOF_REUSED is special: the reuse is external state, not one of the 12
// circuit fields, so the circuit cannot attest a REJECT for it — the
// platform itself says such a task has no proof to submit and is excluded
// from the reliability bonus. The handler therefore answers REJECT with NO
// proof/public_signals fields for this trap only.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_STATE_FILE = join(HERE, '..', '..', 'state', 'gatekeeper-seen.json');

// In-memory seen-set: proof_tx (lowercased) -> task_id. File-backed when a
// state file is configured (local dev). NOTE: on Vercel the filesystem is
// ephemeral per instance, so the in-memory set is the live one there;
// a cold start loses it (documented limitation — see README).
export class SeenSet {
  constructor(stateFile = null) {
    this.stateFile = stateFile;
    this.map = new Map();
    if (stateFile) {
      try {
        const data = JSON.parse(readFileSync(stateFile, 'utf8'));
        for (const [k, v] of Object.entries(data)) this.map.set(k, v);
      } catch { /* no prior state — start empty */ }
    }
  }
  // Returns the task_id that first used this proof_tx, or undefined.
  firstTask(proofTx) {
    return this.map.get(String(proofTx).toLowerCase());
  }
  record(proofTx, taskId) {
    const key = String(proofTx).toLowerCase();
    if (!this.map.has(key)) {
      this.map.set(key, String(taskId));
      this.persist();
    }
  }
  persist() {
    if (!this.stateFile) return;
    try {
      mkdirSync(dirname(this.stateFile), { recursive: true });
      writeFileSync(this.stateFile, JSON.stringify(Object.fromEntries(this.map), null, 2));
    } catch { /* persistence is best-effort; memory stays authoritative */ }
  }
}

export function decide(input, taskId, seen) {
  const registeredVk = String(input.registered_vk ?? '').toLowerCase();
  const proofVk = String(input.proof_vk ?? '').toLowerCase();
  const minimum = BigInt(input.minimum ?? 0);
  const publicBalance = BigInt(input.public_balance ?? 0);
  const expiryBlock = BigInt(input.expiry_block ?? 0);
  const currentBlock = BigInt(input.current_block ?? 0);
  const recipient = String(input.recipient ?? '').toLowerCase();
  const conditionRecipient = String(input.condition_recipient ?? '').toLowerCase();
  const amount = BigInt(input.amount ?? 0);
  const maxTransfer = BigInt(input.max_transfer ?? 0);
  const proofTx = String(input.proof_tx ?? '').toLowerCase();

  if (!registeredVk || !proofVk || proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (proofTx) {
    const prevTask = seen.firstTask(proofTx);
    if (prevTask !== undefined && prevTask !== String(taskId)) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    // First sight of this proof_tx (and the VK matched): record it now,
    // before the remaining checks — a later task reusing it is a reuse
    // even if this task turns out to be another trap.
    if (prevTask === undefined) seen.record(proofTx, taskId);
  }
  if (publicBalance < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (currentBlock >= expiryBlock) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (!recipient || !conditionRecipient || recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (amount > maxTransfer) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

export { DEFAULT_STATE_FILE };
