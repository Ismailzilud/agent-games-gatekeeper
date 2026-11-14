// HTTP-level checks against any running gatekeeper agent (Node or Deno
// edition). Usage: node harness-http.mjs <baseUrl> <secret>
// Expects the server to run WITHOUT Kurier (proof_tx not asserted) unless
// EXPECT_PROOF_TX=1 is set in the environment.
import { sign } from '../src/server.mjs';

const base = process.argv[2];
const SECRET = process.argv[3];
const expectTx = process.env.EXPECT_PROOF_TX === '1';
let failures = 0;
function check(label, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${label} ${extra}`);
  if (!cond) failures += 1;
}
async function post(path, bodyObj, { secret = SECRET } = {}) {
  const raw = JSON.stringify(bodyObj);
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(secret, raw) },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* null */
  }
  return { status: res.status, json, sigOk: res.headers.get('x-agent-games-signature') === sign(SECRET, text) };
}
let seq = 1000;
function task(mutate = {}) {
  seq += 1;
  const t = {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_d_550e8400-e29b-41d4-a716-${String(446655440000 + seq)}`,
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
  return t;
}
{
  const res = await fetch(base + '/healthz');
  check('healthz', res.status === 200 && (await res.json()).ok === true);
}
{
  const pf = {
    type: 'agent-games.preflight.v1',
    agent_id: 'agt_test',
    issued_at: new Date().toISOString(),
    nonce: 'nonce-d1',
  };
  const r = await post('/agent', pf);
  check('preflight', r.status === 200 && r.json.ok === true && r.sigOk);
}
const validTask = task();
{
  const r = await post('/agent', validTask);
  check(
    'valid APPROVE + proof',
    r.json.decision === 'APPROVE' &&
      r.json.reason_code === 'VALID_CONDITION' &&
      !!r.json.proof &&
      r.json.public_signals?.length === 13 &&
      (!expectTx || typeof r.json.proof_tx === 'string') &&
      r.sigOk,
  );
}
for (const [code, input] of [
  ['VK_SUBSTITUTION', { proof_vk: '0x' + 'c'.repeat(64) }],
  ['AMOUNT_OVERFLOW', { amount: '1001' }],
]) {
  const r = await post('/agent', task({ input }));
  check(`trap ${code}`, r.json.decision === 'REJECT' && r.json.reason_code === code && !!r.json.proof);
}
{
  const r = await post('/agent', task({ input: { proof_tx: validTask.input.proof_tx } }));
  check('PROOF_REUSED', r.json.reason_code === 'PROOF_REUSED' && !r.json.proof);
}
{
  const r = await post('/agent', task(), { secret: 'wrong-secret-wrong-secret-wrong-00' });
  check('bad signature 401', r.status === 401);
}
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
