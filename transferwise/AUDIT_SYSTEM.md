# TransferWise high-impact audit system

## Mission
Audit only public repositories owned by `transferwise`, excluding `transferwise/pipelinewise`, for defensible **P0/P1/P2** findings. An already concrete **P3** may be completed when its exploit path and Wise-specific impact are demonstrated. Do not spend scheduled work on generic P4/P5 issues, hardening-only observations, scanner output, sample credentials, or third-party-only bugs.

## Five evidence gates
- **G0 Scope + attacker:** exact `transferwise/<repo>`, not excluded, with a realistic attacker-controlled entry point.
- **G1 Relevance:** exact upstream commit and the shipped/relevant trust boundary are identified.
- **G2 Reproduction:** a bounded, non-destructive PoC executes with an honest/negative control. A code smell or scanner match is insufficient.
- **G3 Security effect:** an independent invariant proves unauthorized code execution, privilege, data/value control, release/repository compromise, or similarly concrete Wise-specific harm.
- **G4 Severity + quality:** P0/P1/P2 or exceptional P3 is justified from observed effect; duplicate review is recorded; reproduction is sanitized and deterministic.

Only G0-G4 may be called CONFIRMED/submission-ready. A failed test is BLOCKED, a holding control is NOT REPORTABLE, and a source-only lead is CANDIDATE.

## Concurrency / ownership
A-E must write only beneath their own `transferwise/<lane>/` directory except for immutable reads of shared policy/config. Do not edit another lane. Do not use `transferwise/latest.md` as a concurrent scratchpad; it is the branch-level summary only.

Each lane owns:
- `PROBES.json`: max 3 active hypotheses; retire negatives instead of endlessly mutating them.
- `latest.md`: exact repo/SHA, experiment, result, gate status, and one next decisive test.
- `evidence/`: raw safe logs, controls and minimal fixtures.
- `submissions/`: only G0-G4-complete packages.

## Run contract
1. Read this file, the program config, lane PROBES and lane latest.
2. Pick **one** new falsifiable high-impact hypothesis. Prefer attack outcome over broad code review.
3. Confirm scope before checkout. Never touch `pipelinewise`.
4. Pin exact target commit. Inspect only enough source to map attacker input -> trust boundary -> security effect.
5. Build the smallest safe reproduction with a negative/honest control. Use local/CI fixtures; do not access live Wise accounts, validate leaked credentials, disrupt services, or exploit third parties.
6. Reproduce in at least two materially distinct inputs/states where stateful, and use an independent oracle for the claimed violation.
7. Record the counterexample: the condition under which the issue is not exploitable.
8. Stop low-impact work immediately. P4/P5 and speculative P3 do not consume future runs.
9. If G0-G4 passes, stop hunting and build a sanitized Bugcrowd-ready bundle. Never auto-submit.

## Priority interpretation
Severity follows demonstrated impact, not the dangerousness of a primitive. For example, `shell=True` with no attacker-controlled path is not a finding; `write-all` without an untrusted execution path is not a finding; a vulnerable third-party dependency without Wise-specific exploitability is not rewardable under the supplied scope.

## Lane map
- **A — CI/CD & repository trust:** Actions, PR/fork boundaries, tokens, releases, signing, package publication, repository compromise.
- **B — AuthN/AuthZ & signing:** authorization, OAuth/session/token, signatures, idempotency/financial-integrity boundaries in Wise-owned code.
- **C — Code execution & unsafe data flow:** command/template/build execution, unsafe deserialization/parsing and injection with concrete impact.
- **D — Infrastructure & deployment integrity:** Wise-specific IaC/cloud/deployment trust and privilege escalation, reproduced without live infrastructure access.
- **E — Cross-repo & supply chain:** dependency/build/release/artifact/package trust across Wise repositories; reject third-party-only bugs.
