// Steal-the-VFY end-to-end harness: drives the real request handler
// in-process (like scripts/agent-games-test.mjs) with the registered
// aggressive strategy (params 10,12,3,0,0,0,0,0 + fixed test salt),
// replays the sample turn envelopes, and checks every response:
//   - HTTP 200 + a valid x-agent-games-signature over the raw response body
//   - the action the policy selects (incl. the <= opponent boundary and
//     the strict < self boundary, both recomputed for the aggressive set)
//   - `amount` present ONLY for EXTRACT (omitted for HOLD / FORTIFY)
//   - the Groth16 policy proof verifies locally against the vfy-policy VK
//   - the 9 public signals match the turn (binding, commitment, matchId
//     encoding, turn, balances, action, amount, circuitVersion)
//   - publicInputsHash recomputes from the same values
//   - a replayed turn returns the byte-identical response
//   - a wrong strategyCommitment hash in the envelope does not change
//     the proof (the registered commitment is used)
//   - malformed envelopes (400), bad HMAC (401), unknown eventId (400),
//     and Steal disabled without a salt (503)
//   - Gatekeeper preflight still works through the same handler
// Run: `npm run harness:steal` (needs no secrets — uses a throwaway test
// secret and a fixed test salt). Kurier is NOT called on the Steal path.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleAgentRequest, createState } from '../src/agent-games/server.mjs';
import { verifyStealLocally } from '../src/agent-games/steal-prove.mjs';
import { hmacHex } from '../src/agent-games/hmac.mjs';
import {
  computeBinding,
  computeCommitment,
  computePublicInputsHash,
  encodeMatchId,
  parseSalt,
  parseStealPublicSignals,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
} from '../src/agent-games/steal-circuit.mjs';
import { parseStrategyParams } from '../src/agent-games/steal-policy.mjs';
import { stealIdempotencyKey } from '../src/agent-games/uuidv5.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SECRET = 'test-secret-' + randomBytes(8).toString('hex');
const TEST_PARAMS = '10,12,3,0,0,0,0,0';
const TEST_SALT = '42424242424242424242';
const state = createState(); // in-memory, fresh per run
const env = {
  AGENT_GAMES_HMAC_SECRET: SECRET,
  KURIER_API_KEY: '',
  STEAL_VFY_PARAMS: TEST_PARAMS,
  STEAL_VFY_SALT: TEST_SALT,
};

let passed = 0;
let failed = 0;
function check(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS ${label}`); }
  else { failed++; console.log(`  FAIL ${label} ${extra}`); }
}

async function post(envelope, secret = SECRET, useState = state, useEnv = env) {
  const rawBody = Buffer.from(JSON.stringify(envelope), 'utf8');
  return handleAgentRequest({
    method: 'POST', path: '/agent',
    headers: { 'x-agent-games-signature': hmacHex(secret, rawBody) },
    rawBody, env: useEnv, state: useState, log: () => {},
  });
}

function loadSample(name, commitmentHex) {
  const raw = readFileSync(join(HERE, '..', 'tests', 'samples', name), 'utf8');
  return JSON.parse(raw.replaceAll('__TEST_COMMITMENT_HEX__', commitmentHex));
}

const params = parseStrategyParams(TEST_PARAMS);
const salt = parseSalt(TEST_SALT);
const commitment = await computeCommitment(params, salt);
console.log(`[steal-harness] test commitment: ${commitment.hex}`);

// ---- Turn cases (expected outcomes under the aggressive params) --------
const cases = [
  { file: 'steal-extract.json', action: 'EXTRACT', amount: 10, self: '100', opp: '100' },
  { file: 'steal-fortify.json', action: 'FORTIFY', amount: null, self: '10', opp: '100' },
  // Reference hold samples become EXTRACT under the aggressive thresholds
  // (opp 5 and 8 are both > 3) — the policy correctly does NOT hold.
  { file: 'steal-hold.json', action: 'EXTRACT', amount: 10, self: '100', opp: '5' },
  { file: 'steal-boundary.json', action: 'EXTRACT', amount: 10, self: '100', opp: '8' },
  { file: 'steal-self-boundary.json', action: 'EXTRACT', amount: 10, self: '18', opp: '100' },
  // Aggressive boundaries: opp == params[2] (3) must HOLD (inclusive);
  // self == params[1] (12) must EXTRACT (strict <); opp == 4 extracts.
  { file: 'steal-hold-aggressive.json', action: 'HOLD', amount: null, self: '100', opp: '3' },
  { file: 'steal-self-boundary-aggressive.json', action: 'EXTRACT', amount: 10, self: '12', opp: '100' },
  { file: 'steal-opp-4.json', action: 'EXTRACT', amount: 10, self: '100', opp: '4' },
];

for (const c of cases) {
  console.log(`\n[${c.file}] expect ${c.action}`);
  const body = loadSample(c.file, commitment.hex);
  const matchId = body.matchId;
  const turn = body.turn;
  const t0 = Date.now();
  const res = await post(body);
  const j = JSON.parse(res.body);
  check('status 200', res.status === 200, `got ${res.status}: ${res.body.slice(0, 200)}`);
  check('echoes matchId', j?.matchId === matchId);
  check('echoes turn', j?.turn === turn);
  const action = j?.action;
  check('action type matches', action?.type === c.action, `got ${action?.type}`);
  if (c.amount === null) {
    check('HOLD/FORTIFY omits amount', action !== undefined && !('amount' in action));
  } else {
    check('EXTRACT carries amount', action?.amount === c.amount, `got ${action?.amount}`);
  }
  check('response is HMAC-signed', res.headers['x-agent-games-signature'] === hmacHex(SECRET, res.body));
  check(
    'idempotencyKey is a deterministic UUID v5 per turn',
    typeof j?.idempotencyKey === 'string' &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(j.idempotencyKey) &&
      j.idempotencyKey === stealIdempotencyKey(matchId, turn)
  );
  const pp = j?.policyProof;
  check('policyProof present', pp !== undefined && typeof pp === 'object');
  check('policyProof circuitVersion is v1', pp?.circuitVersion === 'v1');
  const proof = pp?.proof ?? null;
  const sigs = pp?.public_signals ?? null;
  check('proof present', proof !== null && typeof proof === 'object');
  check('9 public signals', Array.isArray(sigs) && sigs.length === 9);
  if (proof && Array.isArray(sigs) && sigs.length === 9) {
    check('proof verifies against the vfy-policy VK', await verifyStealLocally(sigs, proof));
    const parsed = parseStealPublicSignals(sigs);
    const matchField = encodeMatchId(matchId);
    const binding = await computeBinding(matchField, BigInt(turn), STEAL_CIRCUIT_VERSION);
    check('signal[0] binding = Poseidon(matchId, turn, circuitVersion)', parsed.binding === binding.toString());
    check('signal[1] commitment', parsed.commitment === commitment.decimal);
    check('signal[2] matchId encoding', parsed.matchId === matchField.toString());
    check('signal[3] turnNumber', parsed.turnNumber === String(turn));
    check('signal[4] selfBalance', parsed.selfBalance === c.self);
    check('signal[5] opponentBalance', parsed.opponentBalance === c.opp);
    check('signal[6] action code', parsed.action === STEAL_ACTION_CODE[c.action].toString());
    check('signal[7] amount', parsed.amount === String(c.amount ?? 0));
    check('signal[8] circuitVersion', parsed.circuitVersion === '1');
    const expectedHash = computePublicInputsHash({
      commitment: BigInt(commitment.decimal),
      matchId: matchField,
      turnNumber: BigInt(turn),
      selfBalance: BigInt(c.self),
      opponentBalance: BigInt(c.opp),
      action: STEAL_ACTION_CODE[c.action],
      amount: BigInt(c.amount ?? 0),
      circuitVersion: STEAL_CIRCUIT_VERSION,
    });
    check('publicInputsHash recomputes', pp?.publicInputsHash === expectedHash);
    check('response cached for replay', state.stealResponses.has(`vfy:${matchId}:${turn}`));
  }
  check('turn answered under 5 min', Date.now() - t0 < 300_000, `${Date.now() - t0}ms`);
}

// ---- Replay: same turn again -> byte-identical response -----------------
console.log('\n[replay steal-extract.json turn 1]');
{
  const body = loadSample('steal-extract.json', commitment.hex);
  const first = await post(body);
  const second = await post(body);
  check('replay status 200', second.status === 200, `got ${second.status}`);
  check('replay body is byte-identical', second.body === first.body);
  check('replay signature identical', second.headers['x-agent-games-signature'] === first.headers['x-agent-games-signature']);
}

// ---- Wrong / missing strategyCommitment in the envelope -----------------
console.log('\n[envelope commitment handling]');
{
  const wrong = loadSample('steal-extract.json', commitment.hex);
  wrong.turn = 11;
  wrong.strategyCommitment = { hash: '0x0000000000000000000000000000000000000000000000000000000000000001' };
  const res = await post(wrong);
  check('wrong envelope hash still returns 200', res.status === 200, `got ${res.status}: ${res.body.slice(0, 160)}`);
  const sigs = JSON.parse(res.body)?.policyProof?.public_signals ?? null;
  if (Array.isArray(sigs) && sigs.length === 9) {
    check('proof still uses the registered commitment', parseStealPublicSignals(sigs).commitment === commitment.decimal);
  } else {
    check('proof present with wrong envelope hash', false, 'no signals');
  }

  const missing = loadSample('steal-extract.json', commitment.hex);
  missing.turn = 12;
  delete missing.strategyCommitment;
  const res2 = await post(missing);
  check('missing strategyCommitment still returns 200', res2.status === 200, `got ${res2.status}`);
}

// ---- Malformed envelopes / auth ----------------------------------------
console.log('\n[envelope + auth failures]');
{
  const noState = loadSample('steal-extract.json', commitment.hex);
  noState.turn = 13;
  delete noState.state;
  check('missing state => 400', (await post(noState)).status === 400);

  const badMatch = loadSample('steal-extract.json', commitment.hex);
  badMatch.turn = 14;
  badMatch.matchId = 'not-a-match-id!!';
  check('unparseable matchId => 400', (await post(badMatch)).status === 400);

  const unknownEvent = loadSample('steal-extract.json', commitment.hex);
  unknownEvent.eventId = 'steal-the-something-else';
  check('unknown eventId => 400', (await post(unknownEvent)).status === 400);

  const body = loadSample('steal-extract.json', commitment.hex);
  body.turn = 15;
  check('wrong secret => 401', (await post(body, 'wrong-secret')).status === 401);
}

// ---- Steal disabled without a salt (fresh state, no STEAL_VFY_SALT) -----
console.log('\n[steal disabled]');
{
  const disabledState = createState();
  const disabledEnv = { AGENT_GAMES_HMAC_SECRET: SECRET, KURIER_API_KEY: '' };
  const body = loadSample('steal-extract.json', commitment.hex);
  body.turn = 16;
  const res = await post(body, SECRET, disabledState, disabledEnv);
  check('no salt => 503 steal_not_configured', res.status === 503 && JSON.parse(res.body)?.error === 'steal_not_configured', `got ${res.status}: ${res.body.slice(0, 120)}`);
}

// ---- Gatekeeper path untouched through the same handler ------------------
console.log('\n[gatekeeper path untouched]');
{
  const raw = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' }), 'utf8');
  const out = await handleAgentRequest({
    method: 'POST', path: '/agent',
    headers: { 'x-agent-games-signature': hmacHex(SECRET, raw) },
    rawBody: raw, env, state, log: () => {},
  });
  const body = JSON.parse(out.body);
  check('preflight still 200', out.status === 200 && body.ok === true && body.protocolVersion === 'v1');
  const unknown = await post({ type: 'agent-games.unknown.v1' });
  check('unknown type still 400', unknown.status === 400);
}

console.log(`\n[steal-harness] ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
