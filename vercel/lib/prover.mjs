// Lazy proving for the serverless edition: snarkjs and the circuit files are
// loaded on the first proof request only, so health, signature checks and
// preflight never pay the proving stack's cold-start cost. The proof is
// verified locally against the official verification key before it leaves.
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { buildWitness, FIELD } from './protocol.mjs';

let snark = null;
let WASM = null;
let ZKEY = null;
let vkPromise = null;

async function load() {
  if (snark) return snark;
  snark = await import('snarkjs');
  WASM = readFileSync(new URL('../circuits/gatekeeper.wasm', import.meta.url));
  ZKEY = readFileSync(new URL('../circuits/gatekeeper_final.zkey', import.meta.url));
  return snark;
}

export async function prove(task, decision) {
  const { groth16, zKey } = await load();
  if (!vkPromise) vkPromise = zKey.exportVerificationKey(ZKEY);
  const vk = await vkPromise;
  const salt = BigInt('0x' + randomBytes(32).toString('hex')) % FIELD;
  const { witness, inputs } = buildWitness(task, decision, salt);
  const result = await groth16.fullProve(witness, WASM, ZKEY);
  if (!Array.isArray(result.publicSignals) || result.publicSignals.length !== 13) {
    throw new Error('BAD_SIGNAL_COUNT');
  }
  for (let i = 0; i < inputs.length; i += 1) {
    if (result.publicSignals[i + 1] !== inputs[i]) throw new Error('SIGNAL_MISMATCH');
  }
  const ok = await groth16.verify(vk, result.publicSignals, result.proof);
  if (!ok) throw new Error('LOCAL_VERIFY_FAILED');
  return { proof: result.proof, public_signals: result.publicSignals };
}
