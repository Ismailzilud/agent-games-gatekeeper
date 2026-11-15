// Agent state on Upstash Redis (REST). Same contract as the sqlite edition:
// claim() classifies a task delivery, saveReply() stores the final reply,
// useNonce() burns a preflight nonce once. Task and proof-ref records persist
// for the whole event (proof reuse is checked across rounds).
export class State {
  constructor(url, token) {
    this.url = url.replace(/\/$/, '');
    this.token = token;
  }

  async cmd(...args) {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(args),
    });
    if (!res.ok) throw new Error('STATE_HTTP_' + res.status);
    const data = await res.json();
    if (data.error) throw new Error('STATE_ERROR');
    return data.result;
  }

  async claim(taskId, bodyDigest, proofRef) {
    const taskKey = 'task:' + taskId;
    const priorRaw = await this.cmd('GET', taskKey);
    if (priorRaw) {
      const prior = JSON.parse(priorRaw);
      if (prior.bodyDigest === bodyDigest) return { kind: 'cached', reply: prior.reply };
      return { kind: 'conflict' };
    }
    const placeholder = JSON.stringify({
      bodyDigest,
      reply: { decision: 'REJECT', reason_code: 'INCOMPLETE_TASK' },
    });
    const set = await this.cmd('SET', taskKey, placeholder, 'NX');
    if (set !== 'OK') {
      const againRaw = await this.cmd('GET', taskKey);
      if (againRaw) {
        const again = JSON.parse(againRaw);
        if (again.bodyDigest === bodyDigest) return { kind: 'cached', reply: again.reply };
      }
      return { kind: 'conflict' };
    }
    const refKey = 'ref:' + proofRef.toLowerCase();
    const seen = await this.cmd('GET', refKey);
    if (!seen) await this.cmd('SET', refKey, taskId);
    return { kind: seen ? 'reused' : 'new' };
  }

  async saveReply(taskId, bodyDigest, reply) {
    await this.cmd('SET', 'task:' + taskId, JSON.stringify({ bodyDigest, reply }));
  }

  async useNonce(value) {
    const set = await this.cmd('SET', 'nonce:' + value, '1', 'NX', 'PX', '120000');
    return set === 'OK';
  }
}
