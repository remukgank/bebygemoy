// Fetch the official Gatekeeper circuit artifacts at build time.
// The wasm/zkey are binary and cannot be pushed through the GitHub
// connector, so the repo stores no binaries: this script downloads them
// from the official public URL and verifies the sha256 hashes recorded
// in docs/endpoints.md §1.3 (discovery 2026-11-16). Idempotent: files
// with a matching hash are left alone. Run: `node scripts/fetch-circuits.mjs`
// (also the Vercel build command — see vercel.json).
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'assets', 'agent-games');
const BASE = 'https://agentgames.zkverify.io/circuits/';
const FILES = {
  'gatekeeper.wasm': 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  'gatekeeper_final.zkey': 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
};

mkdirSync(OUT, { recursive: true });
for (const [name, sha] of Object.entries(FILES)) {
  const dest = join(OUT, name);
  if (existsSync(dest)) {
    const cur = createHash('sha256').update(readFileSync(dest)).digest('hex');
    if (cur === sha) { console.log(`${name}: present, sha256 OK`); continue; }
    console.log(`${name}: present but hash mismatch (got ${cur.slice(0, 12)}…), re-downloading`);
  }
  const res = await fetch(BASE + name);
  if (!res.ok) throw new Error(`download ${name} failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = createHash('sha256').update(buf).digest('hex');
  if (got !== sha) throw new Error(`download ${name} hash mismatch: got ${got}, want ${sha}`);
  writeFileSync(dest, buf);
  console.log(`${name}: downloaded ${buf.length} bytes, sha256 OK`);
}

// (Re)generate the verification key from the zkey (fast, deterministic).
const snarkjs = await import('snarkjs');
const vk = await snarkjs.zKey.exportVerificationKey(join(OUT, 'gatekeeper_final.zkey'));
writeFileSync(join(OUT, 'gatekeeper_vk.json'), JSON.stringify(vk, null, 2));
console.log(`gatekeeper_vk.json: written (nPublic=${vk.nPublic}, curve=${vk.curve})`);
