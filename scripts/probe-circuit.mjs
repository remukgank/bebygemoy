// Probe: export gatekeeper VK + run fullProve on a sample VALID task + local verify.
import * as snarkjs from 'snarkjs';
import { readFileSync, writeFileSync } from 'node:fs';
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

const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
writeFileSync('assets/agent-games/gatekeeper_vk.json', JSON.stringify(vk, null, 2));
console.log('vk: protocol=%s curve=%s nPublic=%d vk_alpha_1_len=%d IC_len=%d',
  vk.protocol, vk.curve, vk.nPublic, vk.vk_alpha_1.length, vk.IC.length);

const task = {
  registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  minimum: '1000', public_balance: '1460',
  expiry_block: '8430000', current_block: '8420000',
  recipient: '0xDe4200000000000000000000000000000000009f01',
  condition_recipient: '0xDe4200000000000000000000000000000000009f01',
  amount: '500', max_transfer: '1000',
  task_id: 'gk_24_9d1',
};
const input = {
  registeredVkHash: toField(task.registered_vk),
  proofVkHash: toField(task.proof_vk),
  minimum: task.minimum,
  publicBalance: task.public_balance,
  expiryBlock: task.expiry_block,
  currentBlock: task.current_block,
  recipient: toField(task.recipient),
  conditionRecipient: toField(task.condition_recipient),
  amount: task.amount,
  maxTransfer: task.max_transfer,
  decision: '1',
  taskId: toField(task.task_id),
  salt: (BigInt('0x' + createHash('sha256').update('probe').digest('hex')) % P).toString(),
};
const t0 = Date.now();
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
console.log('fullProve ms=%d publicSignals=%d', Date.now() - t0, publicSignals.length);
console.log('publicSignals:', JSON.stringify(publicSignals));
const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
console.log('LOCAL VERIFY:', ok);
// Check signals 1..12 equal the task fields as field elements
const expect = [
  toField(task.registered_vk), toField(task.proof_vk), '1000', '1460',
  '8430000', '8420000', toField(task.recipient), toField(task.condition_recipient),
  '500', '1000', '1', toField(task.task_id),
];
console.log('signals[1..12] match task fields:', JSON.stringify(publicSignals.slice(1)) === JSON.stringify(expect));
