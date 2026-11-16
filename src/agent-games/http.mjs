// Local dev server (Node http, no framework). Shares the exact handler
// the Vercel adapter uses, so local harness results transfer 1:1.
import { createServer } from 'node:http';
import { handleAgentRequest, createState } from './server.mjs';
import { DEFAULT_STATE_FILE } from './gatekeeper.mjs';

const PORT = Number(process.env.AGENT_GAMES_PORT || 3000);
const state = createState({ seenStateFile: process.env.AGENT_GAMES_STATE_FILE || DEFAULT_STATE_FILE });
const log = (...a) => console.log(new Date().toISOString(), ...a);

const server = createServer(async (req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname === '/api/agent' ? '/agent' : url.pathname === '/api/health' ? '/health' : url.pathname;
    try {
      const out = await handleAgentRequest({
        method: req.method,
        path,
        headers: req.headers,
        rawBody,
        env: process.env,
        state,
        log,
      });
      res.writeHead(out.status, out.headers);
      res.end(out.body);
    } catch (e) {
      log('handler-threw', String(e?.message ?? e).slice(0, 300));
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal' }));
    }
  });
});

server.listen(PORT, () => {
  log(`agent-games-gatekeeper listening on http://127.0.0.1:${PORT} (POST /agent, GET /health)`);
});
