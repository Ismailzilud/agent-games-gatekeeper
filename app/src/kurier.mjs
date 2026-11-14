// Kurier REST client (zkVerify). The API key travels in the URL path, per
// Kurier's documented API — so URLs and errors from this module must never be
// logged. Redirects are refused.
import { GATEKEEPER_VK_HASH } from './protocol.mjs';

export const KURIER_URLS = {
  mainnet: 'https://api.kurier.xyz/api/v1',
  testnet: 'https://api-testnet.kurier.xyz/api/v1',
};

const sleep = (ms, signal) =>
  new Promise((resolvePromise, rejectPromise) => {
    const t = setTimeout(resolvePromise, ms);
    t.unref();
    if (signal) {
      signal.addEventListener(
        'abort',
        () => {
          clearTimeout(t);
          rejectPromise(new Error('ABORTED'));
        },
        { once: true },
      );
    }
  });

export function createKurier({ apiKey, network = 'mainnet', vkHash = GATEKEEPER_VK_HASH }) {
  const base = KURIER_URLS[network];
  if (!base) throw new Error('UNKNOWN_NETWORK');
  const key = encodeURIComponent(apiKey);

  async function request(path, body, signal) {
    const res = await fetch(`${base}/${path}`, {
      method: body ? 'POST' : 'GET',
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'error',
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error('KURIER_HTTP_' + res.status);
    const text = await res.text();
    if (text.length > 262144) throw new Error('KURIER_RESPONSE_TOO_LARGE');
    return JSON.parse(text);
  }

  // Submit a proof and poll until Finalized. Returns { jobId, txHash }.
  // Throws on Failed, timeout of the poll budget, or malformed responses.
  async function finalize(evidence, { signal, pollBudgetMs = 40000 } = {}) {
    const job = await request(`submit-proof/${key}`, {
      proofType: 'groth16',
      vkRegistered: true,
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      proofData: {
        proof: evidence.proof,
        publicSignals: evidence.public_signals,
        vk: vkHash,
      },
    }, signal);
    if (!job || typeof job.jobId !== 'string' || job.jobId.length < 1) {
      throw new Error('KURIER_BAD_JOB');
    }
    const started = Date.now();
    for (;;) {
      const status = await request(`job-status/${key}/${encodeURIComponent(job.jobId)}`, undefined, signal);
      if (!status || status.jobId !== job.jobId) throw new Error('KURIER_JOB_MISMATCH');
      if (status.status === 'Failed') throw new Error('KURIER_JOB_FAILED');
      if (status.status === 'Finalized') {
        if (typeof status.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(status.txHash)) {
          throw new Error('KURIER_NO_TXHASH');
        }
        return { jobId: job.jobId, txHash: status.txHash };
      }
      if (Date.now() - started > pollBudgetMs) throw new Error('KURIER_POLL_TIMEOUT');
      await sleep(1000, signal);
    }
  }

  return { finalize };
}
