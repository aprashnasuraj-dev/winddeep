# Electroneum A–E Continuous Audit — Master Contract

## Canonical target and workspace

- Audit framework repository: `aprashnasuraj-dev/winddeep`
- Write branch ONLY: `electroneum-sc-master-audit`
- Target source: uploaded `electroneum-sc-master(1).zip`
- Reproducible fallback target: `electroneum/electroneum-sc` at immutable commit `3aeb14db0d6384243302f3a025bdff904dc28bf6`
- The uploaded source was verified against that commit on critical files before scheduling.
- Never write to Electroneum upstream. Never run exploit traffic against public/mainnet/testnet infrastructure. All adversarial validation must be local, fixture-based, simulated, or unit/integration-test based.

## Mission

Continuously deepen Windeep so it can find real system-level vulnerabilities in the pinned Electroneum source for exactly these five classes:

A. Unauthorized or unknown-mechanism minting/burning of native tokens.
B. Consensus manipulation that creates monetary advantage, halts the network, or materially disrupts block publication/finality.
C. Theft of other users' tokens or disclosure/recovery of wallet private keys.
D. Rewriting historical blockchain data and getting the network to accept the altered history.
E. Misrepresenting transaction/block reality to exchanges or third parties through wallet, RPC, API, indexing, or explorer display/interpretation behavior.

Component safety is not sufficient evidence of system safety. Trace full call/data/state paths across consensus, block import, state transition, VM/precompiles/system contracts, RPC, wallet/signing, database, networking, and explorer-facing serialization where relevant.

## Required run loop for every worker

1. Sync/read the latest `electroneum-sc-master-audit` branch. Never force-push.
2. Recover the exact pinned target from the uploaded ZIP when available; otherwise fetch the immutable GitHub commit above.
3. Read this master contract plus the worker's previous state, findings, tests, and cross-worker handoffs.
4. Pick the highest-value unclosed hypothesis in the worker's threat class. Prefer system invariants and attacker-controlled boundaries over keyword scans.
5. Map the full mechanism before testing: source -> validation -> state mutation -> persistence/finality -> externally observed result.
6. Use Windeep's existing integrated analyzers where applicable. When coverage is absent or shallow, implement or strengthen a reusable Windeep analyzer/harness rather than relying on one-off manual reasoning.
7. Add a reproducible regression/adversarial test for every meaningful hypothesis. For Go/EVM/consensus logic, prefer deterministic unit/integration fixtures, differential tests, state-root/accounting invariants, malformed-message/block fixtures, fuzz/property tests, and RPC serialization assertions.
8. Run the narrow test first, then the relevant broader Windeep/target test slice. Record exact command, pass/fail, and evidence.
9. A finding is CONFIRMED only if a test or trace demonstrates an attacker-controlled path violating a stated invariant. Otherwise label it hypothesis, blocked, or disproven. Preserve counterexamples.
10. Commit useful work to `electroneum-sc-master-audit`: analyzers, tests, fixtures, state, and evidence. No speculative code churn.
11. Before any write, re-read the current branch head and any touched shared files. If the branch advanced, reconcile/reapply on the new head. Never overwrite another worker's work.
12. Update cross-worker handoffs whenever a mechanism can affect another threat class.

## Evidence format

Store durable audit material under:
- `reports/electroneum/A/`
- `reports/electroneum/B/`
- `reports/electroneum/C/`
- `reports/electroneum/D/`
- `reports/electroneum/E/`
- shared handoffs: `reports/electroneum/shared/`

Each run should leave a concise state record with:
- target commit;
- files/functions traced;
- invariant being tested;
- attacker control/preconditions;
- test/harness added or strengthened;
- exact execution result;
- finding status: CONFIRMED / HYPOTHESIS / DISPROVEN / BLOCKED;
- severity mechanism if confirmed;
- counterexample or reason a suspected path is not exploitable;
- next highest-value hypothesis;
- handoffs to A–E peers.

Do not report "no vulnerability" merely because a scanner returned clean.

## Windeep strengthening rule

Every run must do at least one of:
- add a new reusable analyzer/check/fixture;
- deepen an existing analyzer's cross-function/cross-component reasoning;
- add an adversarial regression/property/fuzz test;
- close a meaningful hypothesis with reproducible evidence.

Avoid duplicated tools. Integrate additions into Windeep's existing tool registry/config/runtime/tests where appropriate. New tooling must fail safely when optional external binaries are unavailable and must not require an AI API to perform deterministic checks unless the feature is explicitly an optional AI layer.

## Worker ownership

### Worker A — Supply integrity
Primary invariant: native token supply changes only through explicitly authorized protocol mechanisms with correct amount, recipient/source, height/fork rules, and accounting.
Trace all balance creation/destruction paths, genesis/prealloc, rewards, fee accounting/burns, system calls/contracts, migrations, state overrides, import/snapshot paths, integer/unit conversions, exceptional/revert behavior, and any custom Electroneum emission logic.
Test for duplicate rewards, replay/double-application, underflow/overflow/sign/unit errors, bypassed authorization, malformed block/state input, fork-boundary errors, and supply-vs-state-root inconsistencies.

### Worker B — Consensus/economic liveness
Primary invariant: an attacker below the intended trust threshold cannot obtain unauthorized proposer/finality power, create economically advantageous canonical blocks, or halt/materially destabilize publication.
Trace Istanbul/QBFT validator selection, seals/committed seals, quorum math, round/view changes, proposer choice, validator-set transitions, block verification/import, bad-block handling, message authentication/replay, timing, equivocation, fork-choice/finality interaction, and reward attribution.
Test boundary quorum counts, duplicate/forged/replayed seals/messages, malformed extra-data, validator-set transition races, view/round edge cases, timestamp/block-period manipulation, competing commits, and failure recovery.

### Worker C — Asset/key theft
Primary invariants: no attacker-controlled input can move another account's assets without valid authorization; no private key/seed/signing secret can be disclosed or reconstructed through supported interfaces.
Trace transaction sender recovery, chain ID/replay protection, nonce and fee semantics, precompiles/system contracts, personal/accounts/signing APIs, keystore/key derivation/storage/unlock flows, RPC/auth boundaries, logs/errors/crash output, IPC/HTTP/WS exposure, and transaction substitution/malleability.
Use synthetic keys only. Test unauthorized signing, confused-deputy paths, replay/domain-separation failures, malformed signatures, key material leakage, unsafe defaults, and permission-boundary bypasses.

### Worker D — Historical integrity
Primary invariant: once history is final under the protocol's assumptions, an attacker below the intended threshold cannot make altered historical blocks/state become accepted canonical history.
Trace block/header/body/state-root verification, parent linkage, receipts/tx roots, checkpoint/finality logic, ancient/freezer/database paths, snapshot/sync/import/export, rewinds/reorg limits, bad-block caches, consensus verification, validator-set history, and state reconstruction.
Test altered historical headers/bodies/receipts/state, weak verification on sync/import paths, checkpoint bypasses, database/snapshot inconsistencies, deep reorg boundaries, validator-history ambiguity, and acceptance differences between full validation and fast/snapshot paths.

### Worker E — Truthfulness of displayed/served chain data
Primary invariant: RPC/wallet/explorer-facing data cannot cause a relying party to accept a false transaction/block reality that disagrees with canonical validated state.
Trace JSON-RPC block/tx/receipt/log/status/confirmation APIs, pending-vs-canonical semantics, chain ID/network identity, block tags, reorg handling, tx/receipt indexing, bloom/log filters, serialization/quantity encoding, duplicate hashes, error/null semantics, and any explorer-facing APIs/indexers included in the target.
Test canonical-vs-pending confusion, stale/reorged receipt visibility, status/confirmation misreporting, block-number/hash mismatch, malformed/overflowing numeric representation, omitted failure state, duplicate/index collisions, and inconsistent answers across RPC methods for the same object.

## Cross-worker coupling

A finding or mechanism must be handed off when it crosses classes. Examples:
- reward accounting + forged consensus -> A and B;
- consensus acceptance of altered old blocks -> B and D;
- signature/replay bug causing theft and misleading receipt -> C and E;
- RPC canonicality bug that could fool an exchange after reorg -> D and E.

## Output discipline

Prioritize depth over raw issue count. One verified system-level bug is more valuable than dozens of scanner warnings. Separate verified facts, inference, and speculation. Quantify affected thresholds/heights/amounts where possible. Preserve exact source references and tests needed to reproduce.


## Mandatory per-run deliverable — no silent runs

Every scheduled run MUST write a durable Markdown report under its worker directory before it ends, even when no vulnerability is confirmed. Use a timestamped filename such as `RUN_YYYYMMDD_HHMM.md` and update a lightweight `LATEST.md` pointer/summary when practical.

A run is incomplete unless it records all of the following:
1. exact target ZIP SHA-256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` and pinned source commit `3aeb14db0d6384243302f3a025bdff904dc28bf6`;
2. assigned threat class and invariant;
3. concrete files/functions/call paths traced this run;
4. attacker-controlled input or trust boundary analyzed;
5. hypotheses attempted, including at least one negative control/counterexample;
6. exact test/analyzer/fuzz/differential command(s) run and observed result(s);
7. Windeep analyzer/test/harness changes made this run, or a precise explanation of why existing tooling was sufficient;
8. finding state for each hypothesis: CONFIRMED / HYPOTHESIS / DISPROVEN / BLOCKED;
9. remaining coverage gaps;
10. the single highest-value next hypothesis;
11. cross-worker handoffs when relevant;
12. resulting audit-branch commit SHA if repository changes were committed.

Do not end a run after only reading code, running grep, or invoking a generic scanner. Each run must either execute a meaningful adversarial/differential test against the pinned target, or add/strengthen a reusable Windeep capability and immediately execute it against the pinned target.

## Required depth and persistence

Work from invariants and complete attacker-to-impact paths, not issue-count targets. Revisit previously tested areas only when adding a new assumption, execution path, boundary condition, or stronger oracle. Prefer the hardest unclosed hypothesis that could produce material impact.

For each primary hypothesis, actively search for the counterexample that would make it non-exploitable: authorization checks, quorum/finality constraints, state-root verification, replay/domain separation, canonicality checks, amount/unit bounds, cache invalidation, or equivalent system barriers. Component-level safety does not close a system-level hypothesis.

When a hypothesis cannot be resolved because tooling is missing, the run MUST strengthen Windeep with the smallest reusable deterministic analyzer, fixture, harness, differential check, fuzz target, or regression test necessary to resolve it. The new capability must be run in the same audit iteration. Avoid one-off scripts unless they are promoted into reusable Windeep tooling/tests.

## Mandatory confirmed-finding report format

Every CONFIRMED vulnerability must also have a concise technical letter suitable for a busy, skeptical senior engineer. The report must be understandable in 2–3 minutes and use this exact structure:

1. **Impact-focused title**
2. **Summary** — 2–4 sentences stating what is wrong, who can trigger it, concrete impact, and severity
3. **Exact reproduction** — numbered steps from a clean local checkout/fixture
4. **Minimal PoC** — smallest deterministic test, fixture, or command demonstrating the invariant violation
5. **Root cause** — brief and code-specific; omit only when self-evident
6. **Suggested fix** — concrete validation/state-machine/accounting/API change, plus the regression test that should remain
7. **Supporting evidence** — only source references, logs, screenshots, or traces needed to substantiate the claim

Style: clear, direct, active voice; no fluff; no first-person discovery narrative; no generic AI language; front-load impact; keep reproduction effortless; distinguish verified fact from inference and speculation.

## No-finding report standard

A run with no confirmed vulnerability is still required to produce a report. It must state exactly what was tested, which hypotheses were disproven or remain open, which negative controls held, what Windeep coverage was added, and what should be tested next. Never write only “no issue found”, “scanner clean”, or equivalent.
