# Agent Games (zkVerify) — Proof Gatekeeper: study + build record

Updated 2026-11-15 ~06:55 WIB. User registered the account themselves
2026-11-14 (X login); agent build work handed to Muse ("Giliran kamu yang
kerja", reaffirmed 2026-11-15 06:19 WIB "kerjakan ini aja bos").

## Protocol (verified from official pages + live artifacts)

- Task envelope `agent-games.proof-gatekeeper.v1`: task_id (ends with a UUID),
  mode practice|competition, issued_at/deadline_at, input{registered_vk,
  proof_vk, minimum, public_balance, expiry_block, current_block, recipient,
  condition_recipient, amount, max_transfer, proof_tx}.
- Auth: HMAC-SHA256 hex over the RAW body, header `x-agent-games-signature`,
  both directions. Secret comes from the dashboard "Rotate Secret" (one-time
  plaintext) → env AGENT_GAMES_HMAC_SECRET.
- Preflight: platform POSTs {type:"agent-games.preflight.v1", agent_id,
  issued_at, nonce} → reply {ok:true, protocolVersion:"v1"} signed.
- Decision order (platform trap list): VK_SUBSTITUTION (proof_vk !=
  registered_vk) → THRESHOLD_MISMATCH (public_balance < minimum) →
  EXPIRED_CONDITION (expiry_block <= current_block) → RECIPIENT_MISMATCH →
  AMOUNT_OVERFLOW (amount > max_transfer) → else APPROVE / VALID_CONDITION.
  PROOF_REUSED is stateful (seen proof_tx set): REJECT without any proof.
- Response: {decision, reason_code, proof, public_signals, proof_tx} signed;
  proof_tx = the Kurier Finalized txHash of OUR proof (not the task's).
- Circuit: Groth16/BN128, artifacts at agentgames.zkverify.io/circuits/
  gatekeeper.wasm (sha256 be00aefe…) + gatekeeper_final.zkey (adfe95a4…),
  vkHash 0x6b79c601…b0 (mainnet). 13 public signals = 1 commitment output +
  12 public inputs in this order: registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision (1/0), taskId (UUID suffix as hex, mod FIELD);
  plus a private random `salt` witness.
- Kurier: POST https://api.kurier.xyz/api/v1/submit-proof/{API_KEY}
  {proofType:"groth16", vkRegistered:true, proofOptions:{library:"snarkjs",
  curve:"bn128"}, proofData:{proof, publicSignals, vk: VK_HASH}} →
  {jobId, optimisticVerify:"success"}; poll GET /job-status/{KEY}/{jobId}
  until Finalized → txHash. Docs example finalizes in ~16 s. Key signup:
  kurier.xyz (mainnet). API key sits in the URL path — never log URLs.
- Scoring: +12 correct, −6 wrong approve, −3 wrong reject, −2 timeout,
  −2 missing/invalid proof, reliability bonus 0..+5. Rounds: 8 tasks/day,
  13–20 Nov, 17:30 WIB–03:30 WIB (rounds 1–2 of 13–14 Nov already closed).
  Prizes per track: 50k/30k/20k VFY for ranks 1–3. Entry locks while a round
  is open; entry requires preflight pass + ≥1 practice task; prize
  eligibility requires GitHub + wallet connected on the profile.

## Build status (2026-11-15)

- Node edition `app/` (reference): server + prover child process + Kurier +
  sqlite state. Harness 13/13 PASS (health, preflight + nonce replay, valid
  APPROVE with proof + finalized proof_tx, cached redelivery, all 5 traps,
  PROOF_REUSED, bad signature 401, boundary values). Proving ~1–1,6 s,
  proofs verified locally against the official VK.
- Deno Deploy edition `deno/main.ts` (production target): Deno.serve +
  Deno KV state + in-process snarkjs singleThread proving (~0,5 s locally;
  the threaded prover deadlocks under Deno — fullProve needs
  {singleThread:true}; local groth16.verify is skipped on Deno, public
  signals are asserted element-wise instead). HTTP harness 7/7 PASS locally.
- Hosting: Deno Deploy is CLOSED to new signups (winding down, shuts
  April 2027 — found 2026-11-15 07:07 WIB after GitHub login succeeded).
  GitHub Codespaces SSH is blocked by this VM's egress proxy. FINAL:
  **Vercel** (project agent-games-gatekeeper, team Rana-Rene, root dir
  vercel/, Upstash Redis "gatekeeper-state" Sin1 free via KV_* env names).
  Production: https://agent-games-gatekeeper-eta.vercel.app
  Endpoint: /api/agent · health: /api/healthz.
- Vercel edition `vercel/` (api/agent.mjs + lib/, Upstash REST state,
  lazy snarkjs load, local verify kept): local simulation 7/7 PASS.
  PRODUCTION VERIFIED 2026-11-15 08:33 WIB: signed practice-shaped task →
  HTTP 200 in 3,85 s, APPROVE/VALID_CONDITION, 13 public signals, and the
  returned proof VERIFIES against the official VK locally. Preflight →
  {"ok":true,"protocolVersion":"v1"} in 1,2 s. (Note: this VM's egress
  proxy intermittently swallows POST responses from vercel.app — the
  Vercel logs showed the "hanging" probes had in fact completed server-
  side in <1 s with correct 401s. Client-side artifact, not an endpoint
  fault.)
- Finalization policy (all editions, 2026-11-15): Kurier finalization is
  best-effort — the reply always carries the decision + locally verified
  proof; proof_tx is added only when finalization completes in budget.
  A slow relay never flips a correct decision.
- Repo: https://github.com/Ismailzilud/agent-games-gatekeeper (public).

## Remaining (needs the user's accounts, ~10 min together)

1. Agent Games dashboard: user logs in ONCE via live-browser takeover
   (automated X login is blocked on X's side). Then the agent registers
   endpoint https://agent-games-gatekeeper-eta.vercel.app/api/agent,
   rotates the secret, and copies it into the Vercel env
   (AGENT_GAMES_HMAC_SECRET, replacing the temporary test secret) inside
   the same browser session — the secret never passes through chat.
2. Kurier: user signs up at kurier.xyz (email+password, mainnet) → the
   API key is set as KURIER_API_KEY in the Vercel project env.
3. Dashboard: run preflight, then ≥1 practice task; verify scores register.
4. Profile: connect GitHub + wallet (prize eligibility).
5. Play scored rounds 3–8 (next: today 15 Nov 17:30 WIB).
