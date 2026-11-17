// Steal-the-VFY strategy: parameter schema + deterministic policy.
//
// Ported from the Realgood-2 reference (src/policy.ts, TypeScript) to
// JavaScript. The strategy is 8 numbers frozen into the commitment at
// registration time (see steal-circuit.mjs). They cannot change mid-match
// — the circuit re-derives the commitment from the private params, so a
// different parameter set simply cannot produce a valid proof. Changing
// the strategy means computing a new commitment and re-registering it in
// the dashboard between matches.
//
// Meaning of each parameter (verified against the circuit, 2026-11-16):
//   params[0]  extract amount (1..10) — how much VFY one EXTRACT takes.
//   params[1]  fortify threshold — FORTIFY while selfBalance < this.
//   params[2]  hold threshold — HOLD while opponentBalance <= this
//              (INCLUSIVE: at exactly params[2] the circuit only allows
//              HOLD. A strict `<` here is wrong — it makes the agent try
//              to EXTRACT at the boundary and the proof fails.)
//   params[3]  never-extract flag (0 or 1) — when 1, the agent never
//              EXTRACTs: FORTIFY while selfBalance < params[1], else HOLD.
//   params[4..7]  reserved — the circuit requires all four to be 0.
//
// Policy (exactly what the circuit enforces, in this order):
//   1. selfBalance < params[1]  -> FORTIFY (amount 0)
//   2. opponentBalance <= params[2] -> HOLD (amount 0)
//   3. params[3] == 1           -> HOLD (amount 0)
//   4. otherwise                 -> EXTRACT params[0]

export const STEAL_PARAM_COUNT = 8;

/** Registered strategy (aggressive): extract 10, fortify below 12, hold when opponent <= 3. */
export const DEFAULT_STRATEGY_PARAMS = [10n, 12n, 3n, 0n, 0n, 0n, 0n, 0n];

/**
 * Parse + validate a strategy parameter set (e.g. from
 * STEAL_VFY_PARAMS="10,12,3,0,0,0,0,0"). Fails fast on anything the
 * circuit cannot prove — an invalid set must never reach registration.
 */
export function parseStrategyParams(raw) {
  const parts = String(raw).split(',').map((x) => x.trim());
  if (parts.length !== STEAL_PARAM_COUNT) {
    throw new Error(
      `STEAL_VFY_PARAMS must have exactly ${STEAL_PARAM_COUNT} comma-separated integers, got ${parts.length}: ${JSON.stringify(raw)}`
    );
  }
  const params = parts.map((x, i) => {
    if (!/^\d+$/.test(x)) {
      throw new Error(`STEAL_VFY_PARAMS[${i}] must be a non-negative integer, got ${JSON.stringify(x)}`);
    }
    return BigInt(x);
  });
  validateStrategyParams(params);
  return params;
}

/** Range checks matching the circuit's asserts (see the header comment). */
export function validateStrategyParams(params) {
  if (params.length !== STEAL_PARAM_COUNT) {
    throw new Error(`Expected ${STEAL_PARAM_COUNT} strategy params, got ${params.length}`);
  }
  if (params[0] < 1n || params[0] > 10n) {
    throw new Error(`strategyParams[0] (extract amount) must be 1..10, got ${params[0]}`);
  }
  for (const i of [1, 2]) {
    if (params[i] > 1000n) {
      throw new Error(`strategyParams[${i}] (balance threshold) must be 0..1000, got ${params[i]}`);
    }
  }
  if (params[3] !== 0n && params[3] !== 1n) {
    throw new Error(`strategyParams[3] (never-extract flag) must be 0 or 1, got ${params[3]}`);
  }
  for (const i of [4, 5, 6, 7]) {
    if (params[i] !== 0n) {
      throw new Error(`strategyParams[${i}] is reserved and must be 0, got ${params[i]}`);
    }
  }
}

/**
 * The deterministic policy — the ONLY move the circuit can prove for this
 * state under these parameters. No randomness, no model, no state beyond
 * the two balances the platform sent.
 */
export function decideMove(state, params) {
  if (params.length !== STEAL_PARAM_COUNT) {
    throw new Error(`decideMove: expected ${STEAL_PARAM_COUNT} params, got ${params.length}`);
  }
  if (state.selfBalance < params[1]) {
    return { type: 'FORTIFY', amountNum: 0 };
  }
  // NOTE: <=, not <. The circuit rejects EXTRACT at exactly params[2].
  if (state.opponentBalance <= params[2]) {
    return { type: 'HOLD', amountNum: 0 };
  }
  if (params[3] === 1n) {
    return { type: 'HOLD', amountNum: 0 };
  }
  return { type: 'EXTRACT', amountNum: Number(params[0]) };
}
