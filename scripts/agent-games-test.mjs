// Local test harness: replays the exact envelopes the platform sends
// (preflight + 1 valid + 6 traps) through the real handler, asserts the
// decisions/reason codes, verifies every proof locally against the
// circuit VK, checks response signatures, idempotency, and the 401 path.
// Run: `npm run harness` (needs no secrets — uses a throwaway test secret).
// Kurier is NOT called here (no KURIER_API_KEY in env) — the Kurier test
// is scripts/kurier-smoke.mjs (one proof, mainnet).
import { createHash, randomBytes } from 'node:crypto';
import { handleAgentRequest, createState } from '../src/agent-games/server.mjs';
import { verifyLocally } from '../src/agent-games/prove.mjs';
import { hmacHex } from '../src/agent-games/hmac.mjs';
import { toFieldString } from '../src/agent-games/field.mjs';

const SECRET = 'test-secret-' + randomBytes(8).toString('hex');
const state = createState(); // in-memory seen-set, fresh per run
const env = { AGENT_GAMES_HMAC_SECRET: SECRET, KURIER_API_KEY: '' };

let passed = 0;
let failed = 0;
function check(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS ${label}`); }
  else { failed++; console.log(`  FAIL ${label} ${extra}`); }
}

async function post(envelope, secret = SECRET) {
  const rawBody = Buffer.from(JSON.stringify(envelope), 'utf8');
  const out = await handleAgentRequest({
    method: 'POST', path: '/agent',
    headers: { 'x-agent-games-signature': hmacHex(secret, rawBody) },
    rawBody, env, state,
    log: (...a) => console.log('   [agent]', ...a),
  });
  return out;
}

function expectSignalsMatch(task, publicSignals) {
  const expect = [
    toFieldString(task.registered_vk), toFieldString(task.proof_vk),
    String(task.minimum), String(task.public_balance),
    String(task.expiry_block), String(task.current_block),
    toFieldString(task.recipient), toFieldString(task.condition_recipient),
    String(task.amount), String(task.max_transfer),
  ];
  return JSON.stringify(publicSignals.slice(1, 11)) === JSON.stringify(expect);
}

const BASE_INPUT = {
  registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: '8430000',
  current_block: '8420000',
  recipient: '0xDe4200000000000000000000000000000000009f01',
  condition_recipient: '0xDe4200000000000000000000000000000000009f01',
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xa800000000000000000000000000000000000000000000000000000000000001',
};
let n = 0;
const task = (overrides = {}) => ({
  type: 'agent-games.proof-gatekeeper.v1',
  task_id: `gk_harness_${++n}`,
  mode: 'practice',
  issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: { ...BASE_INPUT, proof_tx: `0xa8000000000000000000000000000000000000000000000000000000000000${String(n).padStart(2, '0')}`, ...overrides },
});

// 1. Preflight
console.log('== preflight ==');
{
  const raw = Buffer.from(JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' }), 'utf8');
  const out = await handleAgentRequest({
    method: 'POST', path: '/agent',
    headers: { 'x-agent-games-signature': hmacHex(SECRET, raw) },
    rawBody: raw, env, state, log: () => {},
  });
  const body = JSON.parse(out.body);
  check('preflight status 200', out.status === 200);
  check('preflight body', body.ok === true && body.protocolVersion === 'v1');
  check('preflight response signed', out.headers['x-agent-games-signature'] === hmacHex(SECRET, out.body));
}

// 2. Valid task
console.log('== valid ==');
let validTask;
{
  validTask = task();
  const t0 = Date.now();
  const out = await post(validTask);
  const body = JSON.parse(out.body);
  check('valid status 200', out.status === 200);
  check('valid APPROVE', body.decision === 'APPROVE' && body.reason_code === 'VALID_CONDITION');
  check('valid proof present', !!body.proof && Array.isArray(body.public_signals) && body.public_signals.length === 13);
  check('valid proof verifies locally', body.proof ? await verifyLocally(body.public_signals, body.proof) : false);
  check('valid signals echo fields', body.public_signals ? expectSignalsMatch(validTask.input, body.public_signals) : false);
  check('valid decision signal = 1', body.public_signals?.[11] === '1');
  check('valid task_id signal = keccak(task_id)', body.public_signals?.[12] === toFieldString(validTask.task_id));
  check('valid response signed', out.headers['x-agent-games-signature'] === hmacHex(SECRET, out.body));
  check('valid under 60s', Date.now() - t0 < 60000, `${Date.now() - t0}ms`);
}

// 3. Six traps
console.log('== traps ==');
const traps = [
  ['VK_SUBSTITUTION', { proof_vk: '0xa4c10000000000000000000000000000000000000000000000000000000000b8ff' }],
  ['THRESHOLD_MISMATCH', { public_balance: '999' }],
  ['EXPIRED_CONDITION', { current_block: '8430000' }],
  ['RECIPIENT_MISMATCH', { recipient: '0xDe4200000000000000000000000000000000009f02' }],
  ['AMOUNT_OVERFLOW', { amount: '1001' }],
  // PROOF_REUSED: same proof_tx as the valid task, different task_id.
  ['PROOF_REUSED', { proof_tx: validTask.input.proof_tx }],
];
for (const [code, overrides] of traps) {
  const t = task(overrides);
  const out = await post(t);
  const body = JSON.parse(out.body);
  check(`${code} status 200`, out.status === 200);
  check(`${code} REJECT + code`, body.decision === 'REJECT' && body.reason_code === code, JSON.stringify(body).slice(0, 160));
  if (code === 'PROOF_REUSED') {
    check('PROOF_REUSED has no proof (platform rule)', !('proof' in body) && !('public_signals' in body));
  } else {
    check(`${code} proof present`, !!body.proof && body.public_signals?.length === 13);
    check(`${code} proof verifies locally`, body.proof ? await verifyLocally(body.public_signals, body.proof) : false);
    check(`${code} decision signal = 0`, body.public_signals?.[11] === '0');
    check(`${code} signals echo fields`, body.public_signals ? expectSignalsMatch(t.input, body.public_signals) : false);
  }
  check(`${code} response signed`, out.headers['x-agent-games-signature'] === hmacHex(SECRET, out.body));
}

// 4. Idempotency: replay the valid task -> byte-identical response.
console.log('== idempotency ==');
{
  const out = await post(validTask);
  const first = state.responses.get(validTask.task_id);
  check('replay returns cached body', out.body === first.body);
  check('replay returns cached signature', out.headers['x-agent-games-signature'] === first.signature);
}

// 5. Security: bad signature -> 401, task never processed.
console.log('== security ==');
{
  const raw = Buffer.from(JSON.stringify(task()), 'utf8');
  const out = await handleAgentRequest({
    method: 'POST', path: '/agent',
    headers: { 'x-agent-games-signature': hmacHex('wrong-secret', raw) },
    rawBody: raw, env, state, log: () => {},
  });
  check('bad signature -> 401', out.status === 401);
  const out2 = await handleAgentRequest({
    method: 'POST', path: '/agent', headers: {}, rawBody: raw, env, state, log: () => {},
  });
  check('missing signature -> 401', out2.status === 401);
}

console.log(`\nHARNESS: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
