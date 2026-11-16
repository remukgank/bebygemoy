import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, SeenSet } from '../src/agent-games/gatekeeper.mjs';
import { hmacHex, verifyHmac } from '../src/agent-games/hmac.mjs';
import { toFieldString, taskIdToField } from '../src/agent-games/field.mjs';

const base = () => ({
  registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: '8430000',
  current_block: '8420000',
  recipient: '0xDe4200000000000000000000000000000000009f01',
  condition_recipient: '0xDe4200000000000000000000000000000000009f01',
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xa800000000000000000000000000000000000000000000000000000000000001',
});

test('decide: valid task approves', () => {
  const seen = new SeenSet();
  assert.deepEqual(decide(base(), 'gk_1', seen), { decision: 'APPROVE', reason_code: 'VALID_CONDITION' });
});

test('decide: each trap maps to its reason code', () => {
  const cases = [
    ['VK_SUBSTITUTION', { proof_vk: '0xa4c10000000000000000000000000000000000000000000000000000000000b8ff' }],
    ['THRESHOLD_MISMATCH', { public_balance: '999' }],
    ['EXPIRED_CONDITION', { current_block: '8430001' }],
    ['RECIPIENT_MISMATCH', { recipient: '0xDe4200000000000000000000000000000000009f02' }],
    ['AMOUNT_OVERFLOW', { amount: '1001' }],
  ];
  for (const [code, over] of cases) {
    const seen = new SeenSet();
    const input = { ...base(), proof_tx: `0xb${code.length}000000000000000000000000000000000000000000000000000000000000`, ...over };
    assert.deepEqual(decide(input, 'gk_x', seen), { decision: 'REJECT', reason_code: code });
  }
});

test('decide: boundaries match the circuit (inclusive threshold/max, strict expiry)', () => {
  const seen = new SeenSet();
  assert.equal(decide({ ...base(), public_balance: '1000' }, 'gk_b1', seen).decision, 'APPROVE');
  assert.equal(decide({ ...base(), amount: '1000' }, 'gk_b2', new SeenSet()).decision, 'APPROVE');
  assert.deepEqual(decide({ ...base(), current_block: '8430000' }, 'gk_b3', new SeenSet()),
    { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' });
});

test('decide: same-task retry is not reuse; other-task reuse is', () => {
  const seen = new SeenSet();
  decide(base(), 'gk_1', seen);
  assert.equal(decide(base(), 'gk_1', seen).decision, 'APPROVE'); // platform retry
  assert.deepEqual(decide(base(), 'gk_2', seen), { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
});

test('decide: VK check is case-insensitive, runs before reuse', () => {
  const seen = new SeenSet();
  const input = { ...base(), registered_vk: base().registered_vk.toUpperCase(), proof_vk: '0x0000000000000000000000000000000000000000000000000000000000000000' };
  assert.deepEqual(decide(input, 'gk_v', seen), { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' });
});

test('hmac: round-trip verifies; tampered body or secret fails', () => {
  const secret = 's3cret';
  const body = Buffer.from('{"a":1}', 'utf8');
  const sig = hmacHex(secret, body);
  assert.equal(verifyHmac(secret, body, sig), true);
  assert.equal(verifyHmac(secret, body, '0x' + sig.toUpperCase()), true);
  assert.equal(verifyHmac(secret, Buffer.from('{"a":2}', 'utf8'), sig), false);
  assert.equal(verifyHmac('other', body, sig), false);
  assert.equal(verifyHmac(secret, body, ''), false);
  assert.equal(verifyHmac(secret, body, 'zz'), false);
});

test('field: hex/dec/keccak conversions are stable and in-field', () => {
  assert.equal(toFieldString('0x10'), '16');
  assert.equal(toFieldString('16'), '16');
  assert.equal(toFieldString('gk_24_9d1'), taskIdToField('gk_24_9d1'));
  assert.notEqual(toFieldString('gk_24_9d1'), toFieldString('gk_24_9d2'));
});
