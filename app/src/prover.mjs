import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { buildWitness, FIELD } from './protocol.mjs';

// Generate a Groth16 proof for (task, decision) in an isolated child process.
// The salt is a fresh random field element per proof: the circuit's first
// public signal is a commitment over the inputs and this salt.
export function prove(task, decision, { timeoutMs = 30000 } = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const salt = BigInt('0x' + randomBytes(32).toString('hex')) % FIELD;
    let built;
    try {
      built = buildWitness(task, decision, salt);
    } catch (err) {
      rejectPromise(err);
      return;
    }
    const child = fork(new URL('./proof-worker.mjs', import.meta.url), [], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      env: {
        PATH: process.env.PATH,
        NODE_ENV: 'production',
        CIRCUIT_WASM: process.env.CIRCUIT_WASM || '',
        CIRCUIT_ZKEY: process.env.CIRCUIT_ZKEY || '',
      },
      serialization: 'json',
    });
    let settled = false;
    const timer = setTimeout(() => finish(new Error('PROVE_TIMEOUT')), timeoutMs);
    timer.unref();
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
      if (err) rejectPromise(err);
      else resolvePromise(value);
    };
    child.once('error', () => finish(new Error('PROVER_UNAVAILABLE')));
    child.once('exit', (code) => {
      if (!settled) finish(new Error('PROOF_GENERATION_FAILED_' + code));
    });
    child.once('message', (value) => {
      if (!value || value.error || !value.proof || !Array.isArray(value.public_signals)) {
        finish(new Error('PROOF_GENERATION_FAILED'));
      } else {
        finish(null, { proof: value.proof, public_signals: value.public_signals });
      }
    });
    child.send(built);
  });
}
