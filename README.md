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

## Run locally

```sh
npm install
node scripts/fetch-circuits.mjs  # downloads gatekeeper.wasm/.zkey (sha256-verified)
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET (+ KURIER_API_KEY)
npm start              # http://127.0.0.1:3000 (POST /agent, GET /health)
npm test               # unit tests (decide/HMAC/field)
npm run harness        # replay: preflight + 1 valid + 6 traps + security
```

Circuit artifacts (`.wasm`/`.zkey`) are **not committed** (binary) —
they are fetched from the official public URL at build time and
verified against the sha256 hashes in `scripts/fetch-circuits.mjs`.

## Status (2026-11-16 ~14:36 WIB)

- **Code + local tests: DONE.** Harness 55/55, unit 7/7, Kurier mainnet smoke Finalized (job `be9bf6f0-e18e-11f1-838e-1e6a0d14f999`). Pushed to `remukgank/bebygemoy` (commit `8b5e2801`).
- **BLOCKED — Vercel team access (needs Beby):** all Vercel team calls 403 (`scope "pandawa88s-projects-9fe21d0c"`, team `team_6VaS732qM9pxS5deW3gML8il`). Beby must grant the Muse Vercel connection access to that team, then retry `create_git_project`. The `authorize_team_access` tool does not exist in the connector.
- **BLOCKED — GitHub link (needs Beby):** agent registration returns `Link your GitHub account in Settings before registering an agent repository.` Beby must Connect GitHub at `https://agentgames.zkverify.io/dashboard/settings` (OAuth, read-only `read:user`, account `remukgank`, ~10 s). After that, re-run `addAgentAction` (`402dde21e58d3876811bfa08cad15281ae37e33c5d`, args `[{name:"bebygemoy-gatekeeper", events:["Proof Gatekeeper"], repoUrl:"https://github.com/remukgank/bebygemoy", endpoint:""}]`) — it returns the HMAC secret (shown once). Then set the endpoint via `updateAgentEndpoint`, run `preflightAgent`, then `dispatchPracticeTask`. Full action map + wire format: `~/workspace/tzero-testnet-full/docs/endpoints.md` §6.

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
