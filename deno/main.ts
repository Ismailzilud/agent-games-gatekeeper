// Proof Gatekeeper agent — Deno Deploy edition.
// Same protocol as the Node edition (../app), adapted to Deno:
// - Deno.serve HTTP handler, HMAC-SHA256 over the raw body, fail closed.
// - snarkjs proving in-process, single-threaded (the threaded prover
//   deadlocks under Deno's worker model). Local groth16.verify is skipped on
//   this runtime for the same reason; instead the public signals are checked
//   element-by-element against the task inputs, and the identical witness
//   pipeline is verified end-to-end under Node in ../app/test.
// - State (seen proof refs, reply cache, preflight nonces) in Deno KV.
// - Kurier finalization via fetch, same REST contract as the Node edition.
// @ts-nocheck
import { groth16 } from "npm:snarkjs@0.7.5";
import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import { parseTask, decide, buildWitness, FIELD } from "../app/src/protocol.mjs";
import { createKurier } from "../app/src/kurier.mjs";
import { randomBytes } from "node:crypto";

const SECRET = Deno.env.get("AGENT_GAMES_HMAC_SECRET") || "";
const AGENT_PATH = Deno.env.get("AGENT_PATH") || "/agent";
const NETWORK = Deno.env.get("NETWORK") || "mainnet";
const KURIER_API_KEY = Deno.env.get("KURIER_API_KEY") || "";
const kurier = KURIER_API_KEY ? createKurier({ apiKey: KURIER_API_KEY, network: NETWORK }) : null;

const WASM = await Deno.readFile(new URL("../circuits/gatekeeper.wasm", import.meta.url));
const ZKEY = await Deno.readFile(new URL("../circuits/gatekeeper_final.zkey", import.meta.url));

const kv = await Deno.openKv();

function sign(raw) {
  return createHmac("sha256", SECRET).update(raw).digest("hex");
}
function authentic(raw, signature) {
  if (typeof signature !== "string" || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = Buffer.from(sign(raw), "hex");
  const given = Buffer.from(signature, "hex");
  return expected.length === given.length && timingSafeEqual(expected, given);
}
const digest = (raw) => createHash("sha256").update(raw).digest("hex");
const reject = (reason_code) => ({ decision: "REJECT", reason_code });
function freshEnough(issuedAt, now) {
  const issued = Date.parse(issuedAt);
  return Number.isFinite(issued) && issued <= now + 5000 && now - issued <= 60000;
}

async function prove(task, decision) {
  const salt = BigInt("0x" + Buffer.from(randomBytes(32)).toString("hex")) % FIELD;
  const { witness, inputs } = buildWitness(task, decision, salt);
  const result = await groth16.fullProve(witness, WASM, ZKEY, undefined, { memorySize: 256 }, { singleThread: true });
  if (!Array.isArray(result.publicSignals) || result.publicSignals.length !== 13) {
    throw new Error("BAD_SIGNAL_COUNT");
  }
  for (let i = 0; i < inputs.length; i += 1) {
    if (result.publicSignals[i + 1] !== inputs[i]) throw new Error("SIGNAL_MISMATCH");
  }
  return { proof: result.proof, public_signals: result.publicSignals };
}

// Atomically claim a task id + proof reference in KV.
// kinds: new | reused | cached(reply) | conflict
async function claim(taskId, bodyDigest, proofRef) {
  const ref = proofRef.toLowerCase();
  const taskKey = ["tasks", taskId];
  const prior = await kv.get(taskKey);
  if (prior.value) {
    if (prior.value.bodyDigest === bodyDigest) return { kind: "cached", reply: prior.value.reply };
    return { kind: "conflict" };
  }
  const placeholder = { bodyDigest, reply: { decision: "REJECT", reason_code: "INCOMPLETE_TASK" } };
  const res = await kv.atomic().check(prior).set(taskKey, placeholder).commit();
  if (!res.ok) {
    const again = await kv.get(taskKey);
    if (again.value && again.value.bodyDigest === bodyDigest) {
      return { kind: "cached", reply: again.value.reply };
    }
    return { kind: "conflict" };
  }
  const refKey = ["refs", ref];
  const seen = await kv.get(refKey);
  if (!seen.value) await kv.set(refKey, taskId);
  return { kind: seen.value ? "reused" : "new" };
}

async function saveReply(taskId, bodyDigest, reply) {
  await kv.set(["tasks", taskId], { bodyDigest, reply });
}

async function useNonce(value) {
  const key = ["nonces", value];
  const prior = await kv.get(key);
  if (prior.value) return false;
  const res = await kv.atomic().check(prior).set(key, Date.now(), { expireIn: 120000 }).commit();
  return res.ok;
}

let active = false;

Deno.serve(async (req) => {
  const started = Date.now();
  const url = new URL(req.url);
  const send = (status, body) => {
    const raw = JSON.stringify(body);
    return new Response(raw, {
      status,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        "x-agent-games-signature": sign(raw),
        "x-content-type-options": "nosniff",
      },
    });
  };
  const fail = (reason, status = 200) => send(status, reject(reason));
  try {
    if (url.pathname === "/healthz" && req.method === "GET") return send(200, { ok: true });
    if (url.pathname !== AGENT_PATH) return fail("NOT_FOUND", 404);
    if (req.method !== "POST") return fail("METHOD_NOT_ALLOWED", 405);
    if ((req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase() !== "application/json") {
      return fail("CONTENT_TYPE", 415);
    }
    if (active) return fail("BUSY", 503);
    active = true;
    try {
      const raw = new Uint8Array(await req.arrayBuffer());
      if (raw.length > 32768) return fail("BODY_TOO_LARGE", 413);
      if (!authentic(raw, req.headers.get("x-agent-games-signature"))) {
        return fail("INVALID_SIGNATURE", 401);
      }
      let json;
      try {
        json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
      } catch {
        return fail("INVALID_JSON", 400);
      }
      let parsed;
      try {
        parsed = parseTask(json);
      } catch (err) {
        return fail(err.code || "INVALID_TASK", 400);
      }
      if (parsed.kind === "preflight") {
        const nonceKey = digest(parsed.agent_id + ":" + parsed.nonce);
        if (!freshEnough(parsed.issued_at, Date.now()) || !(await useNonce(nonceKey))) {
          return fail("STALE_PREFLIGHT", 400);
        }
        return send(200, { ok: true, protocolVersion: "v1" });
      }
      const task = parsed;
      const deadline = Math.min(started + 58000, Date.parse(task.deadline_at) - 500);
      if (
        !freshEnough(task.issued_at, Date.now()) ||
        Date.parse(task.deadline_at) <= Date.parse(task.issued_at) ||
        deadline <= Date.now()
      ) {
        return fail("STALE_TASK");
      }
      const bodyDigest = digest(raw);
      const claimResult = await claim(task.task_id, bodyDigest, task.input.proof_tx);
      if (claimResult.kind === "conflict") return fail("TASK_ID_CONFLICT", 409);
      if (claimResult.kind === "cached") return send(200, claimResult.reply);
      if (claimResult.kind === "reused") {
        const reply = reject("PROOF_REUSED");
        await saveReply(task.task_id, bodyDigest, reply);
        return send(200, reply);
      }
      const candidate = decide(task);
      let evidence;
      try {
        evidence = await prove(task, candidate.decision);
      } catch {
        const reply = reject(Date.now() >= deadline ? "TIMEOUT" : "PROOF_GENERATION_FAILED");
        await saveReply(task.task_id, bodyDigest, reply);
        return send(200, reply);
      }
      if (Date.now() >= deadline) {
        const reply = reject("TIMEOUT");
        await saveReply(task.task_id, bodyDigest, reply);
        return send(200, reply);
      }
      let reply = { ...candidate, proof: evidence.proof, public_signals: evidence.public_signals };
      if (kurier) {
        try {
          const confirmed = await kurier.finalize(evidence, {
            pollBudgetMs: Math.max(1000, deadline - Date.now() - 1500),
          });
          if (Date.now() >= deadline) throw new Error("DEADLINE");
          reply = { ...reply, proof_tx: confirmed.txHash };
        } catch {
          // Best-effort finalization: keep the decision + verified proof,
          // omit proof_tx. Never flip a correct decision over a slow relay.
        }
      }
      if (Date.now() >= deadline) reply = reject("TIMEOUT");
      await saveReply(task.task_id, bodyDigest, reply);
      return send(200, reply);
    } finally {
      active = false;
    }
  } catch {
    return fail("INTERNAL_ERROR");
  }
});
