// Persistent agent state: which proof references have been seen (reuse trap),
// what reply was given for each task id (idempotent redelivery), and preflight
// nonces. Backed by node:sqlite so a restart mid-round loses nothing.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export class State {
  constructor(path) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        body_digest TEXT NOT NULL,
        reply TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS proof_refs (
        ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT PRIMARY KEY,
        expires INTEGER NOT NULL
      );
    `);
  }

  // Claim a task id + proof reference atomically.
  // -> { kind: 'new' }                    first sight of both
  // -> { kind: 'reused' }                 proof ref seen under another task id
  // -> { kind: 'cached', reply }          same task id + same body redelivered
  // -> { kind: 'conflict' }               same task id, different body
  claim(taskId, bodyDigest, proofRef) {
    const ref = proofRef.toLowerCase();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const prior = this.db
        .prepare('SELECT body_digest, reply FROM tasks WHERE id = ?')
        .get(taskId);
      if (prior) {
        this.db.exec('COMMIT');
        if (prior.body_digest === bodyDigest) {
          return { kind: 'cached', reply: JSON.parse(prior.reply) };
        }
        return { kind: 'conflict' };
      }
      const seen = this.db.prepare('SELECT task_id FROM proof_refs WHERE ref = ?').get(ref);
      this.db
        .prepare('INSERT INTO tasks VALUES (?, ?, ?)')
        .run(taskId, bodyDigest, JSON.stringify({ decision: 'REJECT', reason_code: 'INCOMPLETE_TASK' }));
      if (!seen) this.db.prepare('INSERT INTO proof_refs VALUES (?, ?)').run(ref, taskId);
      this.db.exec('COMMIT');
      return { kind: seen ? 'reused' : 'new' };
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* no transaction */
      }
      throw err;
    }
  }

  saveReply(taskId, reply) {
    this.db.prepare('UPDATE tasks SET reply = ? WHERE id = ?').run(JSON.stringify(reply), taskId);
  }

  // Returns true the first time a preflight nonce is presented.
  useNonce(value) {
    this.db.prepare('DELETE FROM nonces WHERE expires < ?').run(Date.now());
    const res = this.db
      .prepare('INSERT OR IGNORE INTO nonces VALUES (?, ?)')
      .run(value, Date.now() + 120000);
    return res.changes === 1;
  }

  close() {
    this.db.close();
  }
}
