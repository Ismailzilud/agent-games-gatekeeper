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
- Hosting decision: Tailscale in this VM is client-only (cannot host);
  cloudflared ignores the egress proxy; SSH tunnels (serveo/pinggy) die on
  the proxy's flaky port-22 CONNECT. Deno Deploy chosen: stable public URL,
  no tunnel, survives VM replacement. Repo committed locally (2071ce9),
  NOT yet pushed — public-repo publication awaits the user's yes.
- Cross-checked against two independent public competitor implementations
  (protocol facts agree); code here is our own.

## Remaining (needs the user's accounts, ~10 min together)

1. User approves publishing the GitHub repo (agent-games-gatekeeper).
2. Deno: user signs in at Deno Deploy with GitHub, creates project from the
   repo (entrypoint deno/main.ts), shares the resulting *.deno.dev URL.
3. Agent Games dashboard (user, logged in): register endpoint
   https://<url>/agent; Rotate Secret → user sets AGENT_GAMES_HMAC_SECRET in
   the Deno project env (secret never passes through chat/Muse).
4. Kurier: user signs up at kurier.xyz (mainnet) → sets KURIER_API_KEY in the
   Deno project env the same way.
5. Dashboard: run preflight, then practice tasks; verify scores register.
6. Profile: connect GitHub + wallet (prize eligibility).
7. Play scored rounds 3–8 (next: today 17:30 WIB).
