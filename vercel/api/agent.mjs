// Proof Gatekeeper — Vercel serverless edition (route: /api/agent).
// Same protocol and fail-closed flow as the Node edition in ../../app:
// HMAC-SHA256 over the raw body before parsing, deterministic decisions,
// locally verified Groth16 proof, best-effort Kurier finalization, signed
// responses. State lives in Upstash Redis (lib/state.mjs).
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { parseTask, decide } from '../lib/protocol.mjs';
import { prove } from '../lib/prover.mjs';
import { createKurier } from '../lib/kurier.mjs';
import { State } from '../lib/state.mjs';

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const kurier = process.env.KURIER_API_KEY
  ? createKurier({ apiKey: process.env.KURIER_API_KEY, network: process.env.NETWORK || 'mainnet' })
  : null;
const state =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new State(process.env.UPSTASH_REDIS_REST_URL, process.env.UPSTASH_REDIS_REST_TOKEN)
    : null;

function sign(raw) {
  return createHmac('sha256', SECRET).update(raw).digest('hex');
}
function authentic(raw, signature) {
  if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = Buffer.from(sign(raw), 'hex');
  const given = Buffer.from(signature, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given);
}
const digest = (raw) => createHash('sha256').update(raw).digest('hex');
const reject = (reason_code) => ({ decision: 'REJECT', reason_code });
function freshEnough(issuedAt, now) {
  const issued = Date.parse(issuedAt);
  return Number.isFinite(issued) && issued <= now + 5000 && now - issued <= 60000;
}

export default async function handler(req, res) {
  const started = Date.now();
  let sent = false;
  const send = (status, body) => {
    if (sent) return;
    sent = true;
    const raw = JSON.stringify(body);
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-agent-games-signature': sign(raw),
      'x-content-type-options': 'nosniff',
    });
    res.end(raw);
  };
  const fail = (reason, status = 200) => send(status, reject(reason));
  try {
    if (req.method !== 'POST') return fail('METHOD_NOT_ALLOWED', 405);
    if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
      return fail('CONTENT_TYPE', 415);
    }
    if (SECRET.length < 32 || !state) return fail('NOT_CONFIGURED', 503);
    const chunks = [];
    let length = 0;
    for await (const chunk of req) {
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > 32768) return fail('BODY_TOO_LARGE', 413);
      chunks.push(bytes);
    }
    const raw = Buffer.concat(chunks);
    if (!authentic(raw, req.headers['x-agent-games-signature'])) {
      return fail('INVALID_SIGNATURE', 401);
    }
    let json;
    try {
      json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    } catch {
      return fail('INVALID_JSON', 400);
    }
    let parsed;
    try {
      parsed = parseTask(json);
    } catch (err) {
      return fail(err.code || 'INVALID_TASK', 400);
    }
    if (parsed.kind === 'preflight') {
      const nonceKey = digest(parsed.agent_id + ':' + parsed.nonce);
      if (!freshEnough(parsed.issued_at, Date.now()) || !(await state.useNonce(nonceKey))) {
        return fail('STALE_PREFLIGHT', 400);
      }
      return send(200, { ok: true, protocolVersion: 'v1' });
    }
    const task = parsed;
    const deadline = Math.min(started + 56000, Date.parse(task.deadline_at) - 500);
    if (
      !freshEnough(task.issued_at, Date.now()) ||
      Date.parse(task.deadline_at) <= Date.parse(task.issued_at) ||
      deadline <= Date.now()
    ) {
      return fail('STALE_TASK');
    }
    const bodyDigest = digest(raw);
    const claim = await state.claim(task.task_id, bodyDigest, task.input.proof_tx);
    if (claim.kind === 'conflict') return fail('TASK_ID_CONFLICT', 409);
    if (claim.kind === 'cached') return send(200, claim.reply);
    if (claim.kind === 'reused') {
      const reply = reject('PROOF_REUSED');
      await state.saveReply(task.task_id, bodyDigest, reply);
      return send(200, reply);
    }
    const candidate = decide(task);
    let evidence;
    try {
      evidence = await prove(task, candidate.decision);
    } catch {
      const reply = reject(Date.now() >= deadline ? 'TIMEOUT' : 'PROOF_GENERATION_FAILED');
      await state.saveReply(task.task_id, bodyDigest, reply);
      return send(200, reply);
    }
    if (Date.now() >= deadline) {
      const reply = reject('TIMEOUT');
      await state.saveReply(task.task_id, bodyDigest, reply);
      return send(200, reply);
    }
    let reply = { ...candidate, proof: evidence.proof, public_signals: evidence.public_signals };
    if (kurier) {
      try {
        const confirmed = await kurier.finalize(evidence, {
          pollBudgetMs: Math.max(1000, deadline - Date.now() - 1500),
        });
        if (Date.now() >= deadline) throw new Error('DEADLINE');
        reply = { ...reply, proof_tx: confirmed.txHash };
      } catch {
        // Best-effort: keep decision + verified proof, omit proof_tx.
      }
    }
    if (Date.now() >= deadline) reply = reject('TIMEOUT');
    await state.saveReply(task.task_id, bodyDigest, reply);
    return send(200, reply);
  } catch {
    return fail('INTERNAL_ERROR');
  }
}
