# Agent Games Gatekeeper — `bebygemoy`

Proof Gatekeeper agent for ZkVerify Agent Games (Season 01). Receives
HMAC-signed tasks, decides deterministically, answers with a local
Groth16 proof (snarkjs, BN128), and submits the proof to Kurier
(mainnet) for on-chain verification — asynchronously, never blocking
the 60-second task deadline.

## How it works

- `POST /agent` — preflight (`agent-games.preflight.v1`) and Gatekeeper
  tasks (`agent-games.proof-gatekeeper.v1`). Every inbound request is
  HMAC-verified over the raw body **before** JSON parsing; every
  response is signed the same way (`x-agent-games-signature`).
- `GET /health` — unauthenticated liveness probe.
- Decision (deterministic, no LLM): the gatekeeper circuit itself is
  the referee — it constrains the decision bit to the correct
  evaluation of the 12 task fields, so a wrong decision fails witness
  generation. Checks, first failing trap wins: `VK_SUBSTITUTION` →
  `PROOF_REUSED` → `THRESHOLD_MISMATCH` → `EXPIRED_CONDITION`
  (strict: `current_block >= expiry_block`) → `RECIPIENT_MISMATCH` →
  `AMOUNT_OVERFLOW`; else `VALID_CONDITION` → APPROVE. When in doubt,
  REJECT (APPROVE-wrong −6, REJECT-wrong −3).
- `PROOF_REUSED` is answered REJECT with **no proof** (the platform
  says such a task has no proof to submit; it is excluded from the
  reliability bonus). Reuse is tracked per `task_id`: a platform retry
  of the same task is not a reuse; the same `proof_tx` under another
  task is.
- Proof: `groth16.fullProve` with the official `gatekeeper.wasm` /
  `gatekeeper_final.zkey` (~0.4 s). Public signals (13) are
  `[hash, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId]`; `taskId` = keccak256(task_id)
  mod FIELD_PRIME.
- Idempotency: responses are cached by `task_id`; a platform retry
  returns the byte-identical earlier response.

## Steal the VFY (added 2026-11-17)

The same `POST /agent` endpoint also answers Steal turns, dispatched
by `eventId == "steal-the-vfy"` (Gatekeeper routing is unchanged).
Each turn the agent returns the one move its committed strategy
selects, plus a Groth16 policy proof (`vfy-policy` circuit, 9 public
signals) that the platform verifies itself — no Kurier submission on
this path.

- **Strategy (aggressive, registered):** `STEAL_VFY_PARAMS=10,12,3,0,0,0,0,0`
  — extract 10, FORTIFY when own balance < 12, HOLD when the opponent
  is at 3 or less (`params[3]=0`, `params[4..7]=0`). The policy is
  deterministic: `selfBalance < params[1]` → FORTIFY; `opponentBalance
  <= params[2]` → HOLD (**inclusive** — at exactly `params[2]` only
  HOLD is provable); `params[3] == 1` → HOLD; otherwise EXTRACT
  `params[0]`. EXTRACT amount must equal `params[0]`; HOLD/FORTIFY
  amount is 0 and the response **omits** the `amount` field entirely
  for them (the platform rejects the turn if it is present, even as 0).
- **Commitment:** `Poseidon(strategyParams[0..7], salt)` — 32-byte hex,
  registered in the dashboard ("Commitment hash"). The salt is private
  randomness (`STEAL_VFY_SALT`, 16 random bytes hex, generated once,
  never shared, never committed). Compute it with
  `npm run steal-commitment`. Changing params or salt produces a
  different commitment and requires re-registration between matches.
- **Binding (public signal 0):** `Poseidon(matchId, turnNumber,
  circuitVersion)` — one valid proof slot per (match, turn, version).
  Public signals (9): `[binding, commitment, matchId, turnNumber,
  selfBalance, opponentBalance, action, amount, circuitVersion]`
  (actions: HOLD=0, FORTIFY=1, EXTRACT=2; circuitVersion=1).
- **Response:** `{ matchId, turn, action: {type, amount?}, policyProof:
  { circuitVersion: "v1", proof, public_signals, publicInputsHash },
  agentTimestamp, idempotencyKey }`. `idempotencyKey` is a deterministic
  UUID v5 of `steal:<matchId>:turn:<turn>`; a platform retry of an
  answered turn gets the byte-identical response from the cache.
- **Disabled without a salt:** if `STEAL_VFY_SALT` is unset, Steal
  turns answer 503 (`steal_not_configured`) and Gatekeeper keeps
  working. A failed local proof verification is a 500 (fail closed),
  never a response with a bad proof.
- **Circuit artifacts:** `vfy-policy.wasm` / `vfy-policy_final.zkey`
  are fetched at build time by `scripts/fetch-circuits.mjs`
  (sha256-verified, same pattern as gatekeeper) and **not committed**;
  `assets/agent-games/vfy-policy_vk.json` (nPublic=9) is committed.

## Run locally

```sh
npm install
node scripts/fetch-circuits.mjs  # downloads gatekeeper + vfy-policy .wasm/.zkey (sha256-verified)
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET (+ KURIER_API_KEY, STEAL_VFY_SALT)
npm start              # http://127.0.0.1:3000 (POST /agent, GET /health)
npm test               # unit tests (decide/HMAC/field + Steal policy/circuit/UUID)
npm run harness        # replay: preflight + 1 valid + 6 traps + security (Gatekeeper)
npm run harness:steal  # replay: 8 Steal turns + replay/commitment/auth/disabled (205 checks)
npm run steal-commitment  # print the Steal strategy commitment for dashboard registration
```

Circuit artifacts (`.wasm`/`.zkey`) are **not committed** (binary) —
they are fetched from the official public URL at build time and
verified against the sha256 hashes in `scripts/fetch-circuits.mjs`.

## Status (2026-11-16 ~15:00 WIB)

- **Code + local tests: DONE.** Harness 55/55, unit 7/7, Kurier mainnet smoke Finalized (job `be9bf6f0-e18e-11f1-838e-1e6a0d14f999`). Pushed to `remukgank/bebygemoy`.
- **Agent REGISTERED.** `addAgentAction` succeeded 2026-11-16 ~15:00 WIB: agentId `3d469c0c-7c07-497f-a1d8-53d65f7a3c7d`, name `bebygemoy-gatekeeper`, event Proof Gatekeeper, dashboard status **pending** (no endpoint yet). HMAC secret (32-byte) saved to the operator's env file (mode 600), never printed/committed. GitHub link blocker is GONE (registration previously rejected with "Link your GitHub account in Settings" now returns ok:true).
- **BLOCKED — Vercel team access (needs Beby):** `create_git_project` still 403 (`scope "pandawa88s-projects-9fe21d0c"`, team `team_6VaS732qM9pxS5deW3gML8il`). The MCP error's own recovery says: grant this MCP connection access to the target team **through Vercel consent or app installation**; "Completing SSO does not add a missing team grant." The CLI fallback is unavailable in this environment (`/opt/hatch/bin/vercel` is the MCP wrapper, not the real CLI). The `authorize_team_access` tool does not exist in the connector.
- **Next after the team grant:** retry `create_git_project` → deploy → GET /health 200 → set Vercel env `AGENT_GAMES_HMAC_SECRET` + `KURIER_API_KEY` → redeploy → `updateAgentEndpoint` (`https://<host>/agent`) → `preflightAgent` until status active → `dispatchPracticeTask` ≥1. Full action map + wire format: `~/workspace/tzero-testnet-full/docs/endpoints.md` §6.

## Deploy (Vercel Hobby)

Repo `remukgank/bebygemoy` is **not yet linked** to Vercel (blocked, see Status above — team access grant pending). Once linked, pushes
to `main` auto-deploy. Env vars in the Vercel dashboard:
`AGENT_GAMES_HMAC_SECRET` (from the Agent Games dashboard, shown once
at agent registration), `KURIER_API_KEY`. Endpoint:
`https://<project>.vercel.app/agent`.

## Known limitations

- **Seen-set on serverless:** the `proof_tx` seen-set lives in memory
  (plus a file when running locally). A Vercel cold start resets it,
  so a `PROOF_REUSED` trap arriving after a cold start can be missed.
  Mitigation is a persistent store (not wired in v1).
- **Kurier polling is best-effort:** submit-proof runs before the
  response (5 s cap, never blocks/fails the task); polling to
  `Finalized` runs in the background and may be cut off when the
  serverless function freezes. The platform verifies the proof in
  our response itself; Kurier is the on-chain audit trail.
