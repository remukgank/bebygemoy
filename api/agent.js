// Vercel serverless adapter for POST /agent.
// Reads the RAW body (required for HMAC verification), then delegates to
// the shared framework-free handler. Module-level state survives warm
// invocations (seen-set + idempotency cache); cold starts reset it.
import { handleAgentRequest, createState } from '../src/agent-games/server.mjs';

const state = createState(); // no file persistence on serverless

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  try {
    const rawBody = await readRawBody(req);
    const out = await handleAgentRequest({
      method: req.method,
      path: '/agent',
      headers: req.headers,
      rawBody,
      env: process.env,
      state,
      log: (...a) => console.log(new Date().toISOString(), ...a),
    });
    res.writeHead(out.status, out.headers);
    res.end(out.body);
  } catch (e) {
    console.error('agent handler threw', String(e?.message ?? e).slice(0, 300));
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal' }));
  }
}
