// Steal-the-VFY turn handler (POST /agent, eventId "steal-the-vfy").
// Ported from the Realgood-2 reference (src/steal-handler.ts, TypeScript).
//
// Flow (fail closed at every step):
//   1. HMAC was already verified by the server handler, over the raw body.
//   2. Parse + validate the turn envelope. Malformed => 400.
//   3. The policy is deterministic (steal-policy.mjs): the move is the ONLY
//      one the circuit can prove for this state under the registered
//      parameters. There is no model, no randomness, no game-state cache.
//   4. Generate the Groth16 policy proof locally and verify it against
//      the exported vfy-policy VK before responding. A failed local
//      verification is a 500, never a response with a bad proof.
//   5. Respond with the documented shape: echo matchId + turn, the
//      action (amount OMITTED for HOLD / FORTIFY — the platform rejects
//      the turn if it is present, even as 0), and policyProof with the
//      circuit version, proof, public signals, and the public-inputs
//      hash the platform recomputes from the game state.
//   6. Replays are answered from the response cache: same turn => same
//      proof => byte-identical response (the idempotency key is a UUID v5
//      derived from matchId + turn, never random), and the platform
//      dedupes on its side via the binding (public signal 0).
//
// Deliberate differences from a working third-party reference
// implementation (DaddyUnikii/zkverify-agent), each verified against the
// circuit (see steal-circuit.mjs):
//   - The opponent threshold is INCLUSIVE (opponentBalance <= params[2]
//     -> HOLD). The reference uses a strict `<`, which makes its agent
//     attempt an unprovable EXTRACT at exactly params[2].
//   - params[3] == 1 (never-extract) is implemented; the reference
//     ignores it and would attempt an unprovable EXTRACT.
//   - The commitment used is ALWAYS the locally computed one (from the
//     params + salt that were registered). If the envelope carries a
//     different strategyCommitment hash, it is logged as a warning —
//     using the envelope's hash would make the proof fail outright,
//     because the circuit re-derives the commitment from OUR params.
//   - No Kurier submission on this path: the platform verifies the
//     policy proof itself (offline); proofReference is an optional
//     on-chain audit pointer per the builder guide. The proof is
//     returned in the response, not gated on a chain transaction.
//   - The idempotency key is deterministic per turn, so a platform
//     retry after a network failure receives the identical response
//     instead of a fresh random key.
import { signResponse } from './hmac.mjs';
import {
  buildStealCircuitInput,
  computePublicInputsHash,
  encodeMatchId,
  parseStealPublicSignals,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
  STEAL_EVENT_ID,
  STEAL_POLICY_PROOF_VERSION,
} from './steal-circuit.mjs';
import { decideMove } from './steal-policy.mjs';
import { proveSteal, verifyStealLocally } from './steal-prove.mjs';
import { stealIdempotencyKey } from './uuidv5.mjs';

function signedJson(status, obj, secret) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (secret) headers['x-agent-games-signature'] = signResponse(secret, body);
  return { status, headers, body };
}

function parseUint(value) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    return BigInt(value.trim());
  }
  return null;
}

function parseDeadlineMs(value) {
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/** Validate the turn envelope. Returns null when it cannot be answered. */
export function parseStealEnvelope(body) {
  if (body === null || typeof body !== 'object') return null;
  if (body.eventId !== STEAL_EVENT_ID) return null;
  if (typeof body.matchId !== 'string' || body.matchId.trim() === '') return null;
  let matchIdField;
  try {
    matchIdField = encodeMatchId(body.matchId);
  } catch {
    return null;
  }
  const turnBig = parseUint(body.turn);
  if (turnBig === null || turnBig > 9007199254740991n) return null;
  if (body.state === null || typeof body.state !== 'object') return null;
  const selfBalance = parseUint(body.state.selfBalance);
  const opponentBalance = parseUint(body.state.opponentBalance);
  if (selfBalance === null || opponentBalance === null) return null;

  let strategyCommitmentHash = null;
  if (body.strategyCommitment !== null && typeof body.strategyCommitment === 'object') {
    if (typeof body.strategyCommitment.hash === 'string' && body.strategyCommitment.hash.trim() !== '') {
      strategyCommitmentHash = body.strategyCommitment.hash.trim();
    }
  }
  const deadlineMs = parseDeadlineMs(body.deadline_at) ?? parseDeadlineMs(body.deadline) ?? null;

  return {
    matchId: body.matchId,
    matchIdField,
    turn: Number(turnBig),
    selfBalance,
    opponentBalance,
    strategyCommitmentHash,
    deadlineMs,
  };
}

class StealDeadlineExceeded extends Error {
  constructor() {
    super('steal turn deadline exceeded');
  }
}

/**
 * Answer one Steal turn.
 * @param {object} body - parsed JSON envelope (HMAC already verified).
 * @param {object} ctx - { secret, steal, stealResponses, log }.
 *   steal is { params, salt, commitmentHex, commitmentDecimal } or null
 *   (null = track not configured, turns answer 503).
 *   stealResponses is a Map cacheKey -> { body, signature } (bounded FIFO).
 */
export async function handleStealTurn(body, ctx) {
  const { secret, log = () => {} } = ctx;

  if (ctx.steal === null) {
    return signedJson(503, { error: 'steal_not_configured' }, secret);
  }
  const steal = ctx.steal;
  const receivedAtMs = Date.now();

  const turn = parseStealEnvelope(body);
  if (turn === null) {
    return signedJson(400, { error: 'invalid_steal_turn' }, secret);
  }

  // Idempotent replay: a platform retry of an already-answered turn gets
  // the byte-identical response (same proof, same idempotency key, same
  // timestamp) instead of a fresh proof run.
  const cacheKey = `vfy:${turn.matchId}:${turn.turn}`;
  const cached = ctx.stealResponses.get(cacheKey);
  if (cached) {
    log('steal-replay', cacheKey);
    return {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': cached.signature },
      body: cached.body,
    };
  }

  // Turn budget: the platform's deadline when present, else the 5-minute
  // turn window from receipt. Keep a 10s reserve to sign and send.
  const deadlineMs = Math.min(turn.deadlineMs ?? Number.POSITIVE_INFINITY, receivedAtMs + 300_000);
  const reserveMs = 10_000;
  const remainingMs = () => deadlineMs - Date.now() - reserveMs;
  const ensureTime = (neededMs) => {
    if (remainingMs() < neededMs) throw new StealDeadlineExceeded();
  };

  try {
    if (
      turn.strategyCommitmentHash !== null &&
      turn.strategyCommitmentHash.toLowerCase() !== steal.commitmentHex.toLowerCase()
    ) {
      log(
        `steal ${turn.matchId}#${turn.turn} envelope strategyCommitment ` +
          `${turn.strategyCommitmentHash} != registered ${steal.commitmentHex} — ` +
          'using the registered commitment; re-register the strategy if the parameters changed.'
      );
    }

    const move = decideMove(
      { selfBalance: turn.selfBalance, opponentBalance: turn.opponentBalance },
      steal.params
    );
    const actionCode = STEAL_ACTION_CODE[move.type];
    log('steal', turn.matchId, `#${turn.turn}`, move.type, `self=${turn.selfBalance}`, `opp=${turn.opponentBalance}`);

    ensureTime(5_000);
    const input = buildStealCircuitInput({
      commitment: BigInt(steal.commitmentDecimal),
      matchId: turn.matchIdField,
      turnNumber: BigInt(turn.turn),
      selfBalance: turn.selfBalance,
      opponentBalance: turn.opponentBalance,
      action: actionCode,
      amount: BigInt(move.amountNum),
      circuitVersion: STEAL_CIRCUIT_VERSION,
      salt: steal.salt,
      strategyParams: steal.params,
    });
    const t0 = Date.now();
    const { proof, publicSignals } = await proveSteal(input);
    // verifyStealLocally takes (publicSignals, proof) — same order as the
    // Gatekeeper's verifyLocally in prove.mjs.
    const ok = await verifyStealLocally(publicSignals, proof);
    if (!ok) throw new Error('local policy-proof verification failed');
    log('steal-proved', turn.matchId, `#${turn.turn}`, `${Date.now() - t0}ms`);

    // Invariant: the proof must assert the move we are returning.
    const parsed = parseStealPublicSignals(publicSignals);
    if (
      parsed.commitment !== steal.commitmentDecimal ||
      parsed.action !== actionCode.toString() ||
      parsed.amount !== String(move.amountNum) ||
      parsed.circuitVersion !== STEAL_CIRCUIT_VERSION.toString()
    ) {
      throw new Error('policy proof public signals do not match the returned move');
    }

    const publicInputsHash = computePublicInputsHash({
      commitment: BigInt(steal.commitmentDecimal),
      matchId: turn.matchIdField,
      turnNumber: BigInt(turn.turn),
      selfBalance: turn.selfBalance,
      opponentBalance: turn.opponentBalance,
      action: actionCode,
      amount: BigInt(move.amountNum),
      circuitVersion: STEAL_CIRCUIT_VERSION,
    });

    const response = {
      matchId: turn.matchId,
      turn: turn.turn,
      // HOLD and FORTIFY must omit `amount` entirely (the platform
      // rejects the turn if it is present, even as 0).
      action:
        move.type === 'EXTRACT'
          ? { type: 'EXTRACT', amount: move.amountNum }
          : { type: move.type },
      policyProof: {
        circuitVersion: STEAL_POLICY_PROOF_VERSION,
        proof,
        public_signals: publicSignals,
        publicInputsHash,
      },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: stealIdempotencyKey(turn.matchId, turn.turn),
    };

    const result = signedJson(200, response, secret);
    ctx.stealResponses.set(cacheKey, { body: result.body, signature: result.headers['x-agent-games-signature'] });
    if (ctx.stealResponses.size > 500) {
      const firstKey = ctx.stealResponses.keys().next().value;
      if (firstKey !== undefined) ctx.stealResponses.delete(firstKey);
    }
    return result;
  } catch (err) {
    if (err instanceof StealDeadlineExceeded) {
      log(`steal ${turn.matchId}#${turn.turn} deadline exceeded`);
    } else {
      log(`steal ${turn.matchId}#${turn.turn} error:`, String(err?.message ?? err).slice(0, 200));
    }
    // Fail closed with a 500 (the platform records a timeout, -1) rather
    // than returning a move with no/invalid proof (-2).
    return signedJson(500, { error: 'internal_error' }, secret);
  }
}
