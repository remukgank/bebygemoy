// Probe 2: does the circuit enforce the decision bit? Expect:
//  - valid inputs + decision 0 -> witness FAILS
//  - trap inputs (vk mismatch) + decision 1 -> witness FAILS
//  - trap inputs + decision 0 -> witness PASSES
//  - boundary current==expiry + decision 1 -> FAILS; + decision 0 -> PASSES
import * as snarkjs from 'snarkjs';
import { createHash } from 'node:crypto';
const WASM = 'assets/agent-games/gatekeeper.wasm';
const ZKEY = 'assets/agent-games/gatekeeper_final.zkey';
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const toField = (v) => {
  const s = String(v).trim();
  let b;
  if (/^0x[0-9a-fA-F]+$/.test(s)) b = BigInt(s);
  else if (/^\d+$/.test(s)) b = BigInt(s);
  else b = BigInt('0x' + createHash('sha3-256').update(Buffer.from(s, 'utf8')).digest('hex'));
  return (b % P).toString();
};
const salt = (BigInt('0x' + randomBytesHex()) % P).toString();
function randomBytesHex() { return createHash('sha256').update(String(Date.now()) + Math.random()).digest('hex'); }
const base = {
  registeredVkHash: toField('0x7d3a00000000000000000000000000000000000000000000000000000000f291'),
  proofVkHash: toField('0x7d3a00000000000000000000000000000000000000000000000000000000f291'),
  minimum: '1000', publicBalance: '1460', expiryBlock: '8430000', currentBlock: '8420000',
  recipient: toField('0xDe4200000000000000000000000000000000009f01'),
  conditionRecipient: toField('0xDe4200000000000000000000000000000000009f01'),
  amount: '500', maxTransfer: '1000', decision: '1',
  taskId: toField('gk_24_9d1'), salt,
};
async function trial(label, input) {
  try {
    const { publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    console.log(label, '-> PROVED, decision signal =', publicSignals[11]);
  } catch (e) {
    console.log(label, '-> WITNESS FAILED:', String(e.message || e).slice(0, 120));
  }
}
await trial('valid + decision=0 (expect FAIL)', { ...base, decision: '0' });
await trial('vk-mismatch + decision=1 (expect FAIL)', { ...base, proofVkHash: toField('0xa4c10000000000000000000000000000000000000000000000000000000000b8ff'), decision: '1' });
await trial('vk-mismatch + decision=0 (expect PROVE)', { ...base, proofVkHash: toField('0xa4c10000000000000000000000000000000000000000000000000000000000b8ff'), decision: '0' });
await trial('current==expiry + decision=1 (expect FAIL)', { ...base, currentBlock: '8430000', decision: '1' });
await trial('current==expiry + decision=0 (expect PROVE)', { ...base, currentBlock: '8430000', decision: '0' });
await trial('balance==minimum + decision=1 (expect PROVE)', { ...base, publicBalance: '1000', decision: '1' });
await trial('amount==max + decision=1 (expect PROVE)', { ...base, amount: '1000', decision: '1' });
