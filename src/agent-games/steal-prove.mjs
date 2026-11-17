// Local Groth16 proving for the Steal-the-VFY (vfy-policy) circuit
// (snarkjs, BN128). Mirrors src/agent-games/prove.mjs (Gatekeeper).
//
// Circuit inputs (10): matchId, turnNumber, action, amount, selfBalance,
// opponentBalance, commitment, circuitVersion, salt (private),
// strategyParams[8] (private).
// Public signals (9): [binding, commitment, matchId, turnNumber,
// selfBalance, opponentBalance, action, amount, circuitVersion].
// The binding (signal 0) = Poseidon(matchId, turnNumber, circuitVersion).
// See steal-circuit.mjs for the verified circuit facts.
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ASSETS = join(HERE, '..', '..', 'assets', 'agent-games');
export const STEAL_WASM = join(ASSETS, 'vfy-policy.wasm');
export const STEAL_ZKEY = join(ASSETS, 'vfy-policy_final.zkey');

let vkCache = null;
export async function getStealVerificationKey() {
  if (!vkCache) {
    try {
      vkCache = JSON.parse(readFileSync(join(ASSETS, 'vfy-policy_vk.json'), 'utf8'));
    } catch {
      // Fall back to exporting from the zkey (e.g. fresh checkout where
      // the build step has not run yet).
      vkCache = await snarkjs.zKey.exportVerificationKey(STEAL_ZKEY);
    }
  }
  return vkCache;
}

export async function verifyStealLocally(publicSignals, proof) {
  const vk = await getStealVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

/**
 * Convert a circuit input object to the plain JSON snarkjs expects:
 * bigints become decimal strings, arrays (strategyParams[8]) stay arrays
 * of decimal strings, everything else becomes a string.
 */
export function stringifyStealInput(input) {
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    if (typeof v === 'bigint') {
      out[k] = v.toString();
    } else if (Array.isArray(v)) {
      out[k] = v.map((e) => (typeof e === 'bigint' ? e.toString() : String(e)));
    } else {
      out[k] = String(v);
    }
  }
  return out;
}

// Generate the proof. Throws if the witness calculation fails — that means
// the inputs violate the circuit (e.g. a move the policy cannot prove).
// Callers must fail closed on throw.
export async function proveSteal(input) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    stringifyStealInput(input),
    STEAL_WASM,
    STEAL_ZKEY,
  );
  return { proof, publicSignals };
}
