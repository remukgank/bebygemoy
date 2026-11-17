// Print the Steal-the-VFY strategy commitment for dashboard registration.
//
// Usage: node scripts/steal-commitment.mjs
// Reads STEAL_VFY_PARAMS + STEAL_VFY_SALT from the environment (or a
// .env file in the repo root — never committed). Never prints the salt —
// it stays secret on the server. The printed commitment hex is public:
// paste it into the Agent Games dashboard ("Commitment hash" in the
// Steal the VFY section). Changing params or salt afterwards produces a
// DIFFERENT commitment and requires re-registration.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStrategyParams, DEFAULT_STRATEGY_PARAMS } from '../src/agent-games/steal-policy.mjs';
import { computeCommitment, parseSalt } from '../src/agent-games/steal-circuit.mjs';

// Minimal .env loader (no dotenv dependency): KEY=VALUE lines, # comments,
// only fills variables not already set in the environment.
const envFile = join(dirname(fileURLToPath(import.meta.url)), '..', '.env');
if (existsSync(envFile)) {
  for (const line of readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || m[1].startsWith('#')) continue;
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].trim().replace(/^['"]|['"]$/g, '');
  }
}

async function main() {
  const paramsRaw = (process.env.STEAL_VFY_PARAMS ?? '').trim() || DEFAULT_STRATEGY_PARAMS.join(',');
  const saltRaw = (process.env.STEAL_VFY_SALT ?? '').trim();
  if (!saltRaw) {
    console.error(
      'STEAL_VFY_SALT is not set. Generate one (random, never reused elsewhere):\n' +
        "  node -e \"console.log('0x' + require('crypto').randomBytes(16).toString('hex'))\"\n" +
        'then put it in .env as STEAL_VFY_SALT=<value> (and as a Vercel env var at deploy time).'
    );
    process.exit(1);
  }
  const params = parseStrategyParams(paramsRaw);
  const salt = parseSalt(saltRaw);
  const commitment = await computeCommitment(params, salt);
  console.log('Strategy Params :', params.map(String).join(','));
  console.log('Commitment (hex):', commitment.hex);
  console.log('Commitment (dec):', commitment.decimal);
  process.exit(0);
}

main().catch((err) => {
  console.error('[steal-commitment] fatal:', String(err?.message ?? err));
  process.exit(1);
});
