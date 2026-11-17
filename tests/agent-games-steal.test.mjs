// Unit tests for the Steal-the-VFY track (policy, circuit helpers, UUID).
// No proving here — the end-to-end harness (scripts/steal-test.mjs)
// replays real turns and verifies Groth16 proofs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseStrategyParams,
  validateStrategyParams,
  decideMove,
  DEFAULT_STRATEGY_PARAMS,
} from '../src/agent-games/steal-policy.mjs';
import {
  computeCommitment,
  computeBinding,
  computePublicInputsHash,
  encodeMatchId,
  parseSalt,
  parseStealPublicSignals,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
} from '../src/agent-games/steal-circuit.mjs';
import { parseStealEnvelope } from '../src/agent-games/steal-handler.mjs';
import { uuidv5, stealIdempotencyKey } from '../src/agent-games/uuidv5.mjs';

// The registered aggressive strategy: extract 10, fortify below 12,
// hold when the opponent is at 3 or less.
const AGGRESSIVE = [10n, 12n, 3n, 0n, 0n, 0n, 0n, 0n];

test('policy: default params are the registered aggressive set', () => {
  assert.deepEqual(DEFAULT_STRATEGY_PARAMS, AGGRESSIVE);
  assert.deepEqual(parseStrategyParams('10,12,3,0,0,0,0,0'), AGGRESSIVE);
});

test('policy: EXTRACT when both sides are healthy, amount = params[0]', () => {
  const move = decideMove({ selfBalance: 100n, opponentBalance: 100n }, AGGRESSIVE);
  assert.deepEqual(move, { type: 'EXTRACT', amountNum: 10 });
});

test('policy: FORTIFY when self < params[1] (strict)', () => {
  assert.equal(decideMove({ selfBalance: 11n, opponentBalance: 100n }, AGGRESSIVE).type, 'FORTIFY');
  assert.equal(decideMove({ selfBalance: 0n, opponentBalance: 100n }, AGGRESSIVE).type, 'FORTIFY');
});

test('policy: self == params[1] is NOT fortify (strict <) -> EXTRACT', () => {
  assert.equal(decideMove({ selfBalance: 12n, opponentBalance: 100n }, AGGRESSIVE).type, 'EXTRACT');
});

test('policy: HOLD when opponent <= params[2] (inclusive)', () => {
  assert.equal(decideMove({ selfBalance: 100n, opponentBalance: 3n }, AGGRESSIVE).type, 'HOLD');
  assert.equal(decideMove({ selfBalance: 100n, opponentBalance: 0n }, AGGRESSIVE).type, 'HOLD');
});

test('policy: opponent == params[2]+1 is NOT hold -> EXTRACT', () => {
  assert.equal(decideMove({ selfBalance: 100n, opponentBalance: 4n }, AGGRESSIVE).type, 'EXTRACT');
});

test('policy: FORTIFY wins over HOLD when both thresholds hit', () => {
  assert.equal(decideMove({ selfBalance: 5n, opponentBalance: 2n }, AGGRESSIVE).type, 'FORTIFY');
});

test('policy: params[3]=1 never EXTRACTs (healthy -> HOLD, low -> FORTIFY)', () => {
  const never = [10n, 12n, 3n, 1n, 0n, 0n, 0n, 0n];
  assert.equal(decideMove({ selfBalance: 100n, opponentBalance: 100n }, never).type, 'HOLD');
  assert.equal(decideMove({ selfBalance: 5n, opponentBalance: 100n }, never).type, 'FORTIFY');
});

test('policy: invalid params are rejected', () => {
  const invalid = [
    ['params[0]=11', '11,12,3,0,0,0,0,0'],
    ['params[0]=0', '0,12,3,0,0,0,0,0'],
    ['params[3]=2', '10,12,3,2,0,0,0,0'],
    ['params[4]=1', '10,12,3,0,1,0,0,0'],
    ['params[7]=1', '10,12,3,0,0,0,0,1'],
    ['only 7 params', '10,12,3,0,0,0,0'],
    ['non-numeric', '10,12,3,0,0,0,0,x'],
    ['threshold > 1000', '10,1001,3,0,0,0,0,0'],
  ];
  for (const [name, raw] of invalid) {
    assert.throws(() => validateStrategyParams(parseStrategyParams(raw)), name);
  }
});

test('circuit: encodeMatchId accepts UUID and 0x hex, rejects out-of-field', () => {
  assert.equal(
    encodeMatchId('9f4e1b2a-1111-2222-3333-444455556666'),
    211752801442691422638169725321264588390n
  );
  assert.equal(encodeMatchId('0x1234'), 0x1234n);
  assert.throws(() => encodeMatchId('0x' + 'ff'.repeat(40)));
  assert.throws(() => encodeMatchId('not-a-match-id!!'));
});

test('circuit: parseSalt accepts decimal and 0x hex, rejects zero', () => {
  assert.equal(parseSalt('12345'), 12345n);
  assert.equal(parseSalt('0x1234'), 0x1234n);
  assert.throws(() => parseSalt('0'));
  assert.throws(() => parseSalt('xyz'));
});

test('circuit: commitment is deterministic and 32-byte hex', async () => {
  const salt = parseSalt('42424242424242424242');
  const c1 = await computeCommitment(AGGRESSIVE, salt);
  const c2 = await computeCommitment(AGGRESSIVE, salt);
  assert.equal(c1.hex, c2.hex);
  assert.equal(c1.decimal, c2.decimal);
  assert.match(c1.hex, /^0x[0-9a-f]{64}$/);
  const other = await computeCommitment(AGGRESSIVE, parseSalt('1'));
  assert.notEqual(other.hex, c1.hex);
});

test('circuit: binding is deterministic and independent of balances', async () => {
  const matchField = encodeMatchId('9f4e1b2a-1111-2222-3333-444455556666');
  const b1 = await computeBinding(matchField, 1n, STEAL_CIRCUIT_VERSION);
  const b2 = await computeBinding(matchField, 1n, STEAL_CIRCUIT_VERSION);
  assert.equal(b1, b2);
  const b3 = await computeBinding(matchField, 2n, STEAL_CIRCUIT_VERSION);
  assert.notEqual(b3, b1);
});

test('circuit: publicInputsHash recomputes deterministically', async () => {
  const salt = parseSalt('42424242424242424242');
  const commitment = await computeCommitment(AGGRESSIVE, salt);
  const args = {
    commitment: BigInt(commitment.decimal),
    matchId: encodeMatchId('9f4e1b2a-1111-2222-3333-444455556666'),
    turnNumber: 1n,
    selfBalance: 100n,
    opponentBalance: 100n,
    action: STEAL_ACTION_CODE.EXTRACT,
    amount: 10n,
    circuitVersion: STEAL_CIRCUIT_VERSION,
  };
  const h1 = computePublicInputsHash(args);
  const h2 = computePublicInputsHash(args);
  assert.equal(h1, h2);
  assert.match(h1, /^0x[0-9a-f]{64}$/);
  assert.notEqual(computePublicInputsHash({ ...args, amount: 9n }), h1);
});

test('circuit: parseStealPublicSignals validates the 9-signal layout', () => {
  const sigs = ['1', '2', '3', '4', '5', '6', '2', '10', '1'];
  const parsed = parseStealPublicSignals(sigs);
  assert.equal(parsed.binding, '1');
  assert.equal(parsed.commitment, '2');
  assert.equal(parsed.action, '2');
  assert.equal(parsed.amount, '10');
  assert.equal(parsed.circuitVersion, '1');
  assert.throws(() => parseStealPublicSignals(['1', '2']));
});

test('envelope: parseStealEnvelope accepts a valid turn, rejects bad ones', () => {
  const good = {
    eventId: 'steal-the-vfy',
    matchId: '9f4e1b2a-1111-2222-3333-444455556666',
    turn: 1,
    state: { selfBalance: '100', opponentBalance: '100' },
    strategyCommitment: { hash: '0xabc' },
    deadline_at: '2026-11-17T12:00:00.000Z',
  };
  const parsed = parseStealEnvelope(good);
  assert.equal(parsed.matchId, good.matchId);
  assert.equal(parsed.turn, 1);
  assert.equal(parsed.selfBalance, 100n);
  assert.equal(parsed.opponentBalance, 100n);
  assert.equal(parsed.strategyCommitmentHash, '0xabc');
  assert.equal(typeof parsed.deadlineMs, 'number');
  assert.equal(parseStealEnvelope({ ...good, eventId: 'other' }), null);
  assert.equal(parseStealEnvelope({ ...good, state: undefined }), null);
  assert.equal(parseStealEnvelope({ ...good, matchId: 'not-a-match-id!!' }), null);
  assert.equal(parseStealEnvelope({ ...good, turn: -1 }), null);
  assert.equal(parseStealEnvelope({ ...good, turn: 'x' }), null);
  assert.equal(parseStealEnvelope(null), null);
});

test('uuidv5: deterministic, valid v5 shape, per-turn key', () => {
  const k1 = stealIdempotencyKey('9f4e1b2a-1111-2222-3333-444455556666', 1);
  const k2 = stealIdempotencyKey('9f4e1b2a-1111-2222-3333-444455556666', 1);
  assert.equal(k1, k2);
  assert.match(k1, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.notEqual(k1, stealIdempotencyKey('9f4e1b2a-1111-2222-3333-444455556666', 2));
  assert.notEqual(k1, stealIdempotencyKey('aaaaaaaa-1111-2222-3333-444455556666', 1));
  assert.equal(uuidv5('6ba7b811-9dad-11d1-80b4-00c04fd430c8', 'test'), uuidv5('6ba7b811-9dad-11d1-80b4-00c04fd430c8', 'test'));
});
