// Local simulation of the Vercel edition: an in-memory Upstash-REST stub plus
// the real api/agent.mjs + api/healthz.mjs handlers on node:http.
import { createServer } from 'node:http';

process.env.AGENT_GAMES_HMAC_SECRET =
  process.env.AGENT_GAMES_HMAC_SECRET || 'test-secret-test-secret-test-secret-42';
process.env.UPSTASH_REDIS_REST_URL = 'http://127.0.0.1:18079';
process.env.UPSTASH_REDIS_REST_TOKEN = 'test-token';

// --- in-memory Redis subset over the Upstash REST shape ---
const store = new Map();
function runCmd(args) {
  const [op, key, ...rest] = args.map(String);
  if (op === 'GET') {
    const e = store.get(key);
    if (!e) return null;
    if (e.expires && e.expires < Date.now()) {
      store.delete(key);
      return null;
    }
    return e.value;
  }
  if (op === 'SET') {
    const value = rest[0];
    const nx = rest.includes('NX');
    const pxIdx = rest.indexOf('PX');
    const existing = store.get(key);
    if (nx && existing && !(existing.expires && existing.expires < Date.now())) return null;
    store.set(key, {
      value,
      expires: pxIdx >= 0 ? Date.now() + Number(rest[pxIdx + 1]) : null,
    });
    return 'OK';
  }
  throw new Error('unsupported op ' + op);
}
const redis = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    try {
      const result = runCmd(JSON.parse(body));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ result }));
    } catch (err) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(err) }));
    }
  });
});
await new Promise((r) => redis.listen(18079, '127.0.0.1', r));

const { default: agentHandler } = await import('../../vercel/api/agent.mjs');
const { default: healthzHandler } = await import('../../vercel/api/healthz.mjs');
const app = createServer((req, res) => {
  if (req.url === '/api/agent') return agentHandler(req, res);
  if (req.url === '/api/healthz') return healthzHandler(req, res);
  res.writeHead(404);
  res.end();
});
await new Promise((r) => app.listen(18080, '127.0.0.1', r));
console.log('vercel-local ready on 18080');
