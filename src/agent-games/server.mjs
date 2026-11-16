// Core request handler for the Gatekeeper agent — framework-free, shared
// by the local Node server and the Vercel serverless adapter.
//
// Security order (rules 1.2-1.3): verify the HMAC over the RAW body
// BEFORE parsing JSON; any failure is 401 and the task is never processed.
// Responses are signed the same way over the raw response body.
// Fail closed everywhere: unknown types, bad JSON, missing secret, and
// proving errors all produce an error response, never an APPROVE.
import { verifyHmac, signResponse } from './hmac.mjs';
import { decide, SeenSet } from './gatekeeper.mjs';
import { proveGatekeeper } from './prove.mjs';
import { submitProof, pollToFinalized } from './kurier.mjs';

export function createState({ seenStateFile = null } = {}) {
  return { seen: new SeenSet(seenStateFile), responses: new Map() };
}

function jsonResponse(status, obj, secret) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (secret) headers['x-agent-games-signature'] = signResponse(secret, body);
  return { status, headers, body };
}

export async function handleAgentRequest({ method, path, headers, rawBody, env, state, log = () => {} }) {
  const secret = env.AGENT_GAMES_HMAC_SECRET || '';
  const kurierApiKey = env.KURIER_API_KEY || '';

  if (method === 'GET' && (path === '/health' || path === '/api/health')) {
    return jsonResponse(200, {
      ok: true,
      service: 'agent-games-gatekeeper',
      track: 'proof-gatekeeper',
      handle: 'bebygemoy',
      time: new Date().toISOString(),
    }, null);
  }
  if (method !== 'POST' || (path !== '/agent' && path !== '/api/agent')) {
    return jsonResponse(404, { error: 'not_found' }, null);
  }
  if (!secret) {
    log('misconfigured: AGENT_GAMES_HMAC_SECRET is not set');
    return jsonResponse(500, { error: 'agent_misconfigured' }, null);
  }
  const signature = headers['x-agent-games-signature'] || headers['X-Agent-Games-Signature'] || '';
  if (!verifyHmac(secret, rawBody, signature)) {
    return jsonResponse(401, { error: 'bad_signature' }, secret);
  }
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return jsonResponse(400, { error: 'bad_json' }, secret);
  }

  if (envelope?.type === 'agent-games.preflight.v1') {
    log('preflight', envelope.agent_id ?? '');
    return jsonResponse(200, { ok: true, protocolVersion: 'v1' }, secret);
  }

  if (envelope?.type !== 'agent-games.proof-gatekeeper.v1') {
    return jsonResponse(400, { error: 'unknown_type', type: String(envelope?.type ?? '') }, secret);
  }

  const taskId = String(envelope.task_id ?? '');
  const input = envelope.input ?? {};
  if (!taskId) return jsonResponse(400, { error: 'missing_task_id' }, secret);

  // Idempotency: the platform may retry a task after a network failure.
  // Return the exact earlier response (same proof, same signature).
  const cached = state.responses.get(taskId);
  if (cached) {
    log('replay', taskId);
    return { status: 200, headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': cached.signature }, body: cached.body };
  }

  const verdict = decide(input, taskId, state.seen);
  const proofTx = String(input.proof_tx ?? '');
  log('task', taskId, verdict.decision, verdict.reason_code);

  // PROOF_REUSED has no proof to submit (platform rule): answer REJECT
  // without proof/public_signals fields.
  if (verdict.reason_code === 'PROOF_REUSED') {
    const res = jsonResponse(200, { decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: proofTx }, secret);
    state.responses.set(taskId, { body: res.body, signature: res.headers['x-agent-games-signature'] });
    return res;
  }

  let proof = null;
  let publicSignals = null;
  try {
    const t0 = Date.now();
    ({ proof, publicSignals } = await proveGatekeeper(input, taskId, verdict.decision));
    log('proved', taskId, `${Date.now() - t0}ms`, `signals=${publicSignals.length}`);
  } catch (e) {
    // The circuit is the referee: a witness failure means our decision
    // disagreed with the circuit's own evaluation. Fail closed with a
    // REJECT and no proof (this should never happen — decide() mirrors
    // the circuit exactly; if it does, the log line is the alarm).
    log('PROVER_ERROR', taskId, String(e?.message ?? e).slice(0, 200));
    const res = jsonResponse(200, { decision: 'REJECT', reason_code: 'PROVER_ERROR', proof_tx: proofTx }, secret);
    state.responses.set(taskId, { body: res.body, signature: res.headers['x-agent-games-signature'] });
    return res;
  }

  const res = jsonResponse(200, {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: proofTx,
    proof,
    public_signals: publicSignals,
  }, secret);
  state.responses.set(taskId, { body: res.body, signature: res.headers['x-agent-games-signature'] });

  // Kurier: submit the proof on-chain (fast POST, 5s cap). Never let it
  // delay or fail the task response; poll to Finalized in the background.
  if (kurierApiKey) {
    try {
      const sub = await submitProof({ apiKey: kurierApiKey, proof, publicSignals });
      const jobId = sub.body?.jobId ?? sub.body?.job_id ?? sub.body?.id ?? null;
      log('kurier-submit', taskId, sub.http, jobId ? `job=${String(jobId).slice(0, 12)}…` : JSON.stringify(sub.body).slice(0, 120));
      if (jobId) {
        pollToFinalized({ apiKey: kurierApiKey, jobId, onStatus: (s) => log('kurier-job', taskId, s) })
          .catch(() => {});
      }
    } catch (e) {
      log('kurier-submit-failed', taskId, String(e?.message ?? e).slice(0, 120));
    }
  }
  return res;
}
