// Local server entry point: `npm start` (reads .env via the shell;
// use `AGENT_GAMES_HMAC_SECRET=... npm start` or a .env loader).
// For one-off runs without a secret the handler returns 500 on /agent
// (fail closed) — the harness sets a test secret itself.
import '../src/agent-games/http.mjs';
