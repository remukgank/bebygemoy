// Kurier client (zkVerify proof verification API, mainnet).
// The gatekeeper circuit's VK is already registered on zkVerify mainnet,
// so submissions use vkRegistered:true + the circuit's vk hash from
// /api/circuit-info (verified live). Never block the 60s task response
// on Kurier: submit-proof is a single fast POST done before answering
// (5s timeout, failure never fails the task response); polling to
// Finalized runs in the background, best-effort.
const BASE = 'https://api.kurier.xyz/api/v1';
// Gatekeeper VK hash, zkVerify mainnet (GET /api/circuit-info, live).
export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

export async function submitProof({ apiKey, proof, publicSignals, timeoutMs = 5000 }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE}/submit-proof/${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
      }),
      signal: ctrl.signal,
    });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 300) }; }
    return { http: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

export async function getJobStatus({ apiKey, jobId, timeoutMs = 10000 }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE}/job-status/${apiKey}/${jobId}`, {
      headers: { Accept: 'application/json' },
      signal: ctrl.signal,
    });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 300) }; }
    return { http: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Poll until the job reaches Finalized/Failed or the deadline passes.
// Returns the last observed status string. Best-effort: never throws.
export async function pollToFinalized({ apiKey, jobId, intervalMs = 5000, maxWaitMs = 300000, onStatus = null }) {
  const deadline = Date.now() + maxWaitMs;
  let last = 'unknown';
  while (Date.now() < deadline) {
    try {
      const { http, body } = await getJobStatus({ apiKey, jobId });
      const status = body?.status ?? body?.state ?? (http === 404 ? 'not-found' : `http-${http}`);
      last = String(status);
      if (onStatus) onStatus(last, body);
      if (/finalized/i.test(last)) return last;
      if (/failed/i.test(last)) return last;
    } catch (e) {
      last = `error:${String(e?.message ?? e).slice(0, 80)}`;
      if (onStatus) onStatus(last, null);
    }
    await sleep(intervalMs);
  }
  return last;
}
