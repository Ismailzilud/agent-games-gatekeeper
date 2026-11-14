// Proof Gatekeeper protocol: task validation, decision policy, circuit inputs.
// Protocol facts are from the official Agent Games build/event pages and the
// published circuit artifacts (gatekeeper.wasm / gatekeeper_final.zkey).

export const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

const UINT32_MAX = 0xffffffffn;
const HEX_RE = /^0x[0-9a-fA-F]{1,64}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const UINT_STR_RE = /^(0|[1-9][0-9]*)$/;
const UUID_SUFFIX_RE =
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function fail(code) {
  const err = new Error(code);
  err.code = code;
  throw err;
}

export function parseUint32(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) > UINT32_MAX) {
      fail('INVALID_INTEGER');
    }
    return BigInt(value);
  }
  if (typeof value !== 'string' || !UINT_STR_RE.test(value)) fail('INVALID_INTEGER');
  const n = BigInt(value);
  if (n > UINT32_MAX) fail('INVALID_INTEGER');
  return n;
}

export function parseHexField(value) {
  if (typeof value !== 'string' || !HEX_RE.test(value)) fail('INVALID_HEX');
  return BigInt(value);
}

export function parseAddress(value) {
  if (typeof value !== 'string' || !ADDRESS_RE.test(value)) fail('INVALID_ADDRESS');
  return BigInt(value);
}

function parseInstant(value) {
  if (typeof value !== 'string') fail('INVALID_TIMESTAMP');
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) fail('INVALID_TIMESTAMP');
  return ms;
}

// Strictly validate an inbound envelope. Returns a normalized task object or
// throws an Error with .code set to a machine-readable reason.
export function parseTask(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) fail('INVALID_TASK');
  if (json.type === 'agent-games.preflight.v1') {
    if (typeof json.agent_id !== 'string' || json.agent_id.length < 1 || json.agent_id.length > 160) {
      fail('INVALID_PREFLIGHT');
    }
    if (typeof json.nonce !== 'string' || json.nonce.length < 1 || json.nonce.length > 256) {
      fail('INVALID_PREFLIGHT');
    }
    parseInstant(json.issued_at);
    return { kind: 'preflight', agent_id: json.agent_id, nonce: json.nonce, issued_at: json.issued_at };
  }
  if (json.type !== 'agent-games.proof-gatekeeper.v1') fail('UNSUPPORTED_TASK_TYPE');
  if (typeof json.task_id !== 'string' || json.task_id.length < 1 || json.task_id.length > 200) {
    fail('INVALID_TASK');
  }
  if (json.mode !== 'practice' && json.mode !== 'competition') fail('INVALID_MODE');
  parseInstant(json.issued_at);
  parseInstant(json.deadline_at);
  const i = json.input;
  if (!i || typeof i !== 'object' || Array.isArray(i)) fail('INVALID_INPUT');
  const task = {
    kind: 'task',
    task_id: json.task_id,
    mode: json.mode,
    issued_at: json.issued_at,
    deadline_at: json.deadline_at,
    input: {
      registered_vk: parseHexField(i.registered_vk),
      proof_vk: parseHexField(i.proof_vk),
      minimum: parseUint32(i.minimum),
      public_balance: parseUint32(i.public_balance),
      expiry_block: parseUint32(i.expiry_block),
      current_block: parseUint32(i.current_block),
      recipient: parseAddress(i.recipient),
      condition_recipient: parseAddress(i.condition_recipient),
      amount: parseUint32(i.amount),
      max_transfer: parseUint32(i.max_transfer),
      proof_tx: i.proof_tx,
    },
  };
  if (typeof i.proof_tx !== 'string' || !HEX_RE.test(i.proof_tx)) fail('INVALID_HEX');
  return task;
}

// The five arithmetic conditions, in the platform's trap order. Proof reuse is
// NOT decided here: it is a stateful check handled by the server (the circuit
// has no input for it).
export function decide(task) {
  const i = task.input;
  if (i.registered_vk !== i.proof_vk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  if (i.public_balance < i.minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (i.expiry_block <= i.current_block) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (i.recipient !== i.condition_recipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (i.amount > i.max_transfer) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// Encode the task id as a field element. Real platform task ids end with a
// UUID; the circuit input is that UUID read as a hex number.
export function taskIdField(taskId) {
  const m = UUID_SUFFIX_RE.exec(taskId);
  if (m) return BigInt('0x' + m[0].replaceAll('-', '')) % FIELD;
  if (/^0x[0-9a-fA-F]+$/.test(taskId)) return BigInt(taskId) % FIELD;
  return null; // unknown format: caller must fail closed
}

// The twelve public inputs, in circuit order. publicSignals[0] of the proof is
// the circuit's commitment output; these twelve follow it.
export function publicInputs(task, decision) {
  const i = task.input;
  const tid = taskIdField(task.task_id);
  if (tid === null) fail('TASK_ID_FORMAT');
  const values = [
    i.registered_vk,
    i.proof_vk,
    i.minimum,
    i.public_balance,
    i.expiry_block,
    i.current_block,
    i.recipient,
    i.condition_recipient,
    i.amount,
    i.max_transfer,
    decision === 'APPROVE' ? 1n : 0n,
    tid,
  ];
  return values.map((v) => (v % FIELD).toString());
}

export const WITNESS_NAMES = [
  'registeredVkHash',
  'proofVkHash',
  'minimum',
  'publicBalance',
  'expiryBlock',
  'currentBlock',
  'recipient',
  'conditionRecipient',
  'amount',
  'maxTransfer',
  'decision',
  'taskId',
];

export function buildWitness(task, decision, salt) {
  const inputs = publicInputs(task, decision);
  const witness = {};
  WITNESS_NAMES.forEach((name, idx) => {
    witness[name] = inputs[idx];
  });
  witness.salt = (salt % FIELD).toString();
  return { witness, inputs };
}
