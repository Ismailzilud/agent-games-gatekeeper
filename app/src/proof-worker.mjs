// Proving runs in a child process: a snarkjs crash or hang must never take the
// HTTP server down with it. Receives { witness } once, replies with
// { proof, public_signals } after verifying the proof locally against the
// official verification key, or { error: true }.
import { groth16, zKey } from 'snarkjs';
import { resolve } from 'node:path';

const WASM = resolve(process.env.CIRCUIT_WASM || 'circuits/gatekeeper.wasm');
const ZKEY = resolve(process.env.CIRCUIT_ZKEY || 'circuits/gatekeeper_final.zkey');

process.once('message', async (msg) => {
  const done = (payload) => {
    if (process.send) process.send(payload, () => process.exit(payload.error ? 1 : 0));
    else process.exit(payload.error ? 1 : 0);
  };
  try {
    const { witness, inputs } = msg;
    const result = await groth16.fullProve(witness, WASM, ZKEY);
    if (!Array.isArray(result.publicSignals) || result.publicSignals.length !== 13) {
      throw new Error('unexpected public signal count');
    }
    for (let i = 0; i < inputs.length; i += 1) {
      if (result.publicSignals[i + 1] !== inputs[i]) throw new Error('public signal mismatch');
    }
    const vk = await zKey.exportVerificationKey(ZKEY);
    const ok = await groth16.verify(vk, result.publicSignals, result.proof);
    if (!ok) throw new Error('local verification failed');
    done({ proof: result.proof, public_signals: result.publicSignals });
  } catch {
    done({ error: true });
  }
});
