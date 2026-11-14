// End-to-end harness: real HTTP server, real proving, mocked Kurier finalize.
// Sends signed envelopes for preflight, a valid task, every trap variety,
// proof reuse, redelivery, and a bad signature; checks decisions, reason
// codes, proof presence, and response signatures.
import { createServer } from 'node:http';
import { createHmac } from 'node:crypto';
import { createHandler, sign } from '../src/server.mjs';
import { State } from '../src/state.mjs';

const SECRET = 'test-secret-test-secret-test-secret-42';
const config = {
  secret: SECRET,
  network: 'testnet',
  agentPath: '/agent',
  port: 0,
  host: '127.0.0.1',
  statePath: ':memory:',
  kurier: null,
};
const fakeFinalize = async () => ({ jobId: 'job_test', txHash: '0x' + 'f'.repeat(64) });
const state = new State(':memory:');
const server = createServer(createHandler(config, state, { finalize: fakeFinalize }));
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

let failures = 0;
function check(label, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${label} ${extra}`);
  if (!cond) failures += 1;
}

async function post(path, bodyObj, { secret = SECRET, signBody = true } = {}) {
  const raw = JSON.stringify(bodyObj);
  const headers = { 'content-type': 'application/json' };
  if (signBody) headers['x-agent-games-signature'] = sign(secret, raw);
  const res = await fetch(base + path, { method: 'POST', headers, body: raw });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  const sigOk = res.headers.get('x-agent-games-signature') === sign(SECRET, text);
  return { status: res.status, json, sigOk };
}

const now = Date.now();
let seq = 0;
function task(mutate = {}) {
  seq += 1;
  const t = {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_t_550e8400-e29b-41d4-a716-${String(446655440000 + seq)}`,
    mode: 'practice',
    issued_at: new Date(Date.now()).toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: '0x' + 'a'.repeat(64),
      proof_vk: '0x' + 'a'.repeat(64),
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0x' + '1'.repeat(40),
      condition_recipient: '0x' + '1'.repeat(40),
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x' + String(seq).padStart(64, '0'),
    },
  };
  if (mutate.input) Object.assign(t.input, mutate.input);
  if (mutate.top) Object.assign(t, mutate.top);
  return t;
}

// health
{
  const res = await fetch(base + '/healthz');
  const j = await res.json();
  check('healthz', res.status === 200 && j.ok === true);
}
// preflight
{
  const pf = {
    type: 'agent-games.preflight.v1',
    agent_id: 'agt_test',
    issued_at: new Date().toISOString(),
    nonce: 'nonce-1',
  };
  const r = await post('/agent', pf);
  check('preflight ok', r.status === 200 && r.json.ok === true && r.json.protocolVersion === 'v1' && r.sigOk);
  const r2 = await post('/agent', pf);
  check('preflight nonce replay rejected', r2.status === 400 && r2.json.reason_code === 'STALE_PREFLIGHT');
}
// valid task
const validTask = task();
{
  const r = await post('/agent', validTask);
  check(
    'valid APPROVE + proof + proof_tx',
    r.json.decision === 'APPROVE' &&
      r.json.reason_code === 'VALID_CONDITION' &&
      !!r.json.proof &&
      Array.isArray(r.json.public_signals) &&
      r.json.public_signals.length === 13 &&
      r.json.proof_tx === '0x' + 'f'.repeat(64) &&
      r.sigOk,
  );
  const r2 = await post('/agent', validTask);
  check('redelivery cached identical', JSON.stringify(r2.json) === JSON.stringify(r.json));
}
// traps
const traps = [
  ['VK_SUBSTITUTION', { proof_vk: '0x' + 'c'.repeat(64) }],
  ['THRESHOLD_MISMATCH', { public_balance: '999' }],
  ['EXPIRED_CONDITION', { current_block: 8430000 }],
  ['RECIPIENT_MISMATCH', { condition_recipient: '0x' + '2'.repeat(40) }],
  ['AMOUNT_OVERFLOW', { amount: '1001' }],
];
for (const [code, input] of traps) {
  const r = await post('/agent', task({ input }));
  check(`trap ${code}`, r.json.decision === 'REJECT' && r.json.reason_code === code && !!r.json.proof && r.sigOk);
}
// proof reuse: same proof_tx as the valid task, new task id
{
  const reused = task({ input: { proof_tx: validTask.input.proof_tx } });
  const r = await post('/agent', reused);
  check(
    'PROOF_REUSED without proof',
    r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED' && !r.json.proof,
  );
}
// bad signature
{
  const r = await post('/agent', task(), { secret: 'wrong-secret-wrong-secret-wrong-00' });
  check('bad signature 401', r.status === 401 && r.json.reason_code === 'INVALID_SIGNATURE');
}
// boundary: balance == minimum approves; amount == cap approves; expiry == current+1 approves
{
  const r = await post(
    '/agent',
    task({ input: { public_balance: '1000', amount: '1000', expiry_block: 8420001 } }),
  );
  check('boundaries APPROVE', r.json.decision === 'APPROVE');
}

server.close();
state.close();
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
