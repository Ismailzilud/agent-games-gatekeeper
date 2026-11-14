// Direct prover test: a valid task and one trap task must both produce
// locally verified proofs whose public signals match the protocol order.
import { parseTask, decide, publicInputs } from '../src/protocol.mjs';
import { prove } from '../src/prover.mjs';

const now = Date.now();
const base = {
  type: 'agent-games.proof-gatekeeper.v1',
  task_id: 'gk_24_550e8400-e29b-41d4-a716-446655440000',
  mode: 'practice',
  issued_at: new Date(now).toISOString(),
  deadline_at: new Date(now + 60000).toISOString(),
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
    proof_tx: '0x' + 'b'.repeat(64),
  },
};

async function run(label, mutate) {
  const raw = structuredClone(base);
  mutate(raw);
  const task = parseTask(raw);
  const decision = decide(task);
  const t0 = Date.now();
  const evidence = await prove(task, decision.decision);
  const ms = Date.now() - t0;
  const expected = publicInputs(task, decision.decision);
  const okSignals =
    evidence.public_signals.length === 13 &&
    evidence.public_signals.slice(1).every((v, i) => v === expected[i]);
  console.log(
    `${label}: decision=${decision.decision}/${decision.reason_code} prove=${ms}ms signals13=${evidence.public_signals.length === 13} orderMatch=${okSignals}`,
  );
  if (!okSignals) process.exitCode = 1;
}

await run('valid', () => {});
await run('vk-trap', (t) => {
  t.input.proof_vk = '0x' + 'c'.repeat(64);
  t.task_id = 'gk_25_550e8400-e29b-41d4-a716-446655440001';
});
console.log('prove-test done');
