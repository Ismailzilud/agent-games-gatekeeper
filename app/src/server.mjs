// Proof Gatekeeper agent server.
// - Verifies x-agent-games-signature (HMAC-SHA256 hex over the RAW body)
//   before any JSON parsing. Fails closed everywhere.
// - Answers preflight envelopes, decides gatekeeper tasks deterministically,
//   attaches a locally verified Groth16 proof, finalizes it via Kurier, and
//   signs every response over its raw body.
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual, createHash } from 'node:crypto';
import { parseTask, decide } from './protocol.mjs';
import { prove } from './prover.mjs';
import { createKurier } from './kurier.mjs';
import { State } from './state.mjs';

export function sign(secret, raw) {
  return createHmac('sha256', secret).update(raw).digest('hex');
}

export function authentic(secret, raw, signature) {
  if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = Buffer.from(sign(secret, raw), 'hex');
  const given = Buffer.from(signature, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

const digest = (raw) => createHash('sha256').update(raw).digest('hex');
const reject = (reason_code) => ({ decision: 'REJECT', reason_code });

function freshEnough(issuedAt, now) {
  const issued = Date.parse(issuedAt);
  return Number.isFinite(issued) && issued <= now + 5000 && now - issued <= 60000;
}

export function loadConfig(env = process.env) {
  const secret = env.AGENT_GAMES_HMAC_SECRET || '';
  if (secret.length < 32) throw new Error('AGENT_GAMES_HMAC_SECRET missing or too short');
  const network = env.NETWORK || 'mainnet';
  if (network !== 'mainnet' && network !== 'testnet') throw new Error('NETWORK must be mainnet|testnet');
  const agentPath = env.AGENT_PATH || '/agent';
  if (!/^\/[a-zA-Z0-9/_-]+$/.test(agentPath)) throw new Error('Invalid AGENT_PATH');
  return {
    secret,
    network,
    agentPath,
    port: Number(env.PORT || 8790),
    host: env.HOST || '127.0.0.1',
    statePath: env.STATE_PATH || './data/state.sqlite',
    kurier: env.KURIER_API_KEY ? createKurier({ apiKey: env.KURIER_API_KEY, network }) : null,
  };
}

export function createHandler(config, state, deps = {}) {
  const doProve = deps.prove || prove;
  const doFinalize =
    deps.finalize || (config.kurier ? (ev, opts) => config.kurier.finalize(ev, opts) : null);
  let active = false;

  return async function handler(req, res) {
    const started = Date.now();
    let sent = false;
    const send = (status, body) => {
      if (sent || res.destroyed) return;
      sent = true;
      const raw = JSON.stringify(body);
      res.writeHead(status, {
        'content-type': 'application/json',
        'cache-control': 'no-store',
        'x-agent-games-signature': sign(config.secret, raw),
        'x-content-type-options': 'nosniff',
      });
      res.end(raw);
    };
    const fail = (reason, status = 200) => send(status, reject(reason));

    try {
      if (req.url === '/healthz' && req.method === 'GET') {
        send(200, { ok: true });
        return;
      }
      if (req.url !== config.agentPath) {
        fail('NOT_FOUND', 404);
        return;
      }
      if (req.method !== 'POST') {
        fail('METHOD_NOT_ALLOWED', 405);
        return;
      }
      if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
        fail('CONTENT_TYPE', 415);
        return;
      }
      if (active) {
        fail('BUSY', 503);
        return;
      }
      active = true;
      try {
        const chunks = [];
        let length = 0;
        for await (const chunk of req) {
          const bytes = Buffer.from(chunk);
          length += bytes.length;
          if (length > 32768) {
            fail('BODY_TOO_LARGE', 413);
            return;
          }
          chunks.push(bytes);
        }
        const raw = Buffer.concat(chunks);
        if (!authentic(config.secret, raw, req.headers['x-agent-games-signature'])) {
          fail('INVALID_SIGNATURE', 401);
          return;
        }
        let json;
        try {
          json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
        } catch {
          fail('INVALID_JSON', 400);
          return;
        }
        let parsed;
        try {
          parsed = parseTask(json);
        } catch (err) {
          fail(err.code || 'INVALID_TASK', 400);
          return;
        }
        if (parsed.kind === 'preflight') {
          const nonceKey = digest(parsed.agent_id + ':' + parsed.nonce);
          if (!freshEnough(parsed.issued_at, Date.now()) || !state.useNonce(nonceKey)) {
            fail('STALE_PREFLIGHT', 400);
            return;
          }
          send(200, { ok: true, protocolVersion: 'v1' });
          return;
        }
        const task = parsed;
        const deadline = Math.min(started + 58000, Date.parse(task.deadline_at) - 500);
        if (
          !freshEnough(task.issued_at, Date.now()) ||
          Date.parse(task.deadline_at) <= Date.parse(task.issued_at) ||
          deadline <= Date.now()
        ) {
          fail('STALE_TASK');
          return;
        }
        const claim = state.claim(task.task_id, digest(raw), task.input.proof_tx);
        if (claim.kind === 'conflict') {
          fail('TASK_ID_CONFLICT', 409);
          return;
        }
        if (claim.kind === 'cached') {
          send(200, claim.reply);
          return;
        }
        if (claim.kind === 'reused') {
          const reply = reject('PROOF_REUSED');
          state.saveReply(task.task_id, reply);
          send(200, reply);
          return;
        }
        const candidate = decide(task);
        let evidence;
        try {
          evidence = await doProve(task, candidate.decision, {
            timeoutMs: Math.max(1000, deadline - Date.now() - 1000),
          });
        } catch {
          const reply = reject(Date.now() >= deadline ? 'TIMEOUT' : 'PROOF_GENERATION_FAILED');
          state.saveReply(task.task_id, reply);
          send(200, reply);
          return;
        }
        if (Date.now() >= deadline) {
          const reply = reject('TIMEOUT');
          state.saveReply(task.task_id, reply);
          send(200, reply);
          return;
        }
        let reply = { ...candidate, proof: evidence.proof, public_signals: evidence.public_signals };
        if (doFinalize) {
          try {
            const confirmed = await doFinalize(evidence, {
              pollBudgetMs: Math.max(1000, deadline - Date.now() - 1500),
            });
            if (Date.now() >= deadline) throw new Error('DEADLINE');
            reply = { ...reply, proof_tx: confirmed.txHash };
          } catch {
            // An APPROVE must never ride on an unfinalized proof; a REJECT
            // keeps its (locally verified) proof and simply has no proof_tx.
            reply =
              candidate.decision === 'REJECT'
                ? reply
                : reject(Date.now() >= deadline ? 'TIMEOUT' : 'FINALIZATION_FAILED');
          }
        }
        if (Date.now() >= deadline) reply = reject('TIMEOUT');
        state.saveReply(task.task_id, reply);
        send(200, reply);
      } finally {
        active = false;
      }
    } catch {
      // Last-resort fail closed: never leave an APPROVE in flight.
      try {
        fail('INTERNAL_ERROR');
      } catch {
        /* socket gone */
      }
    }
  };
}

export function start(config = loadConfig()) {
  const state = new State(config.statePath);
  const server = createServer(createHandler(config, state));
  server.requestTimeout = 60000;
  server.headersTimeout = 10000;
  server.listen(config.port, config.host, () => {
    console.log(
      `proof-gatekeeper listening on ${config.host}:${config.port}${config.agentPath} network=${config.network} kurier=${config.kurier ? 'on' : 'off'}`,
    );
  });
  return { server, state };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start();
}
