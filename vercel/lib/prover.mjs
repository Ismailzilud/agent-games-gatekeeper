// In-process proving for the serverless edition. The witness pipeline is the
// one verified end-to-end in ../../app; here the proof is additionally
// verified locally against the official verification key before it leaves.
import { groth16, zKey } from 'snarkjs';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { buildWitness, FIELD } from './protocol.mjs';

const WASM = readFileSync(new URL('../circuits/gatekeeper.wasm', import.meta.url));
const ZKEY = readFileSync(new URL('../circuits/gatekeeper_final.zkey', import.meta.url));

let vkPromise = null;
function getVk() {
  if (!vkPromise) vkPromise = zKey.exportVerificationKey(ZKEY);
  return vkPromise;
}

export async function prove(task, decision) {
  const salt = BigInt('0x' + randomBytes(32).toString('hex')) % FIELD;
  const { witness, inputs } = buildWitness(task, decision, salt);
  const result = await groth16.fullProve(witness, WASM, ZKEY);
  if (!Array.isArray(result.publicSignals) || result.publicSignals.length !== 13) {
    throw new Error('BAD_SIGNAL_COUNT');
  }
  for (let i = 0; i < inputs.length; i += 1) {
    if (result.publicSignals[i + 1] !== inputs[i]) throw new Error('SIGNAL_MISMATCH');
  }
  const vk = await getVk();
  const ok = await groth16.verify(vk, result.publicSignals, result.proof);
  if (!ok) throw new Error('LOCAL_VERIFY_FAILED');
  return { proof: result.proof, public_signals: result.publicSignals };
}
