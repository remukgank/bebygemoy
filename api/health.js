// Vercel serverless adapter for GET /health (unauthenticated liveness).
import { handleAgentRequest, createState } from '../src/agent-games/server.mjs';

const state = createState();

export default async function handler(req, res) {
  const out = await handleAgentRequest({
    method: req.method,
    path: '/health',
    headers: req.headers,
    rawBody: Buffer.alloc(0),
    env: process.env,
    state,
    log: () => {},
  });
  res.writeHead(out.status, out.headers);
  res.end(out.body);
}
