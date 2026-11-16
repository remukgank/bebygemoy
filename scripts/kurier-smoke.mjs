// Kurier mainnet smoke test: submit ONE proof (from a harness-style valid
// task) and poll job-status until Finalized/Failed. Run once after the
// harness is green. Secrets come from the mode-600 env file — nothing is
// printed. Usage: node scripts/kurier-smoke.mjs
import { readFileSync } from 'node:fs';
import { proveGatekeeper, verifyLocally } from '../src/agent-games/prove.mjs';
import { submitProof, pollToFinalized } from '../src/agent-games/kurier.mjs';

const envFile = readFileSync('/home/hatch/workspace/zkverify-discovery/agent-games-wallet.env', 'utf8');
const apiKey = envFile.match(/^KURIER_API_KEY=(.+)$/m)?.[1]?.trim();
if (!apiKey) { console.error('KURIER_API_KEY not found in the secrets file'); process.exit(1); }

const input = {
  registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  minimum: '1000', public_balance: '1460',
  expiry_block: '8430000', current_block: '8420000',
  recipient: '0xDe4200000000000000000000000000000000009f01',
  condition_recipient: '0xDe4200000000000000000000000000000000009f01',
  amount: '500', max_transfer: '1000',
};
const { proof, publicSignals } = await proveGatekeeper(input, 'gk_kurier_smoke_1', 'APPROVE');
console.log(JSON.stringify({ localVerify: await verifyLocally(publicSignals, proof), signals: publicSignals.length }));
const sub = await submitProof({ apiKey, proof, publicSignals });
console.log(JSON.stringify({ submitHttp: sub.http, bodyKeys: Object.keys(sub.body ?? {}), bodyPreview: JSON.stringify(sub.body).slice(0, 200) }));
const jobId = sub.body?.jobId ?? sub.body?.job_id ?? sub.body?.id ?? null;
if (!jobId) { console.log('no jobId returned — cannot poll'); process.exit(0); }
console.log(JSON.stringify({ jobIdPrefix: String(jobId).slice(0, 8), jobIdLen: String(jobId).length }));
const finalStatus = await pollToFinalized({
  apiKey, jobId, intervalMs: 5000, maxWaitMs: 300000,
  onStatus: (s) => console.log(JSON.stringify({ poll: s, at: new Date().toISOString() })),
});
console.log(JSON.stringify({ finalStatus }));
