# Windeep v6 release checklist

Status: **BLOCKED / DRAFT**.

This is the canonical V6 release checklist. Detailed acceptance criteria and evidence requirements live in `docs/V6_CRITICAL_RELEASE_GATES.md`. PR #34 must remain draft and unmerged until **all ten** blockers below are closed with code, tests, negative controls, and release artifacts.

Do **not** bump `VERSION` to 6.x, tag V6, or publish V6 binaries merely to make CI pass. A scanner cannot guarantee a bounty-worthy vulnerability exists on an arbitrary target; V6 must instead demonstrate that it can produce a reproducible, impact-bearing, human-reviewable submission when a real vulnerability exists and produce zero submission candidates for controlled negative/noise fixtures.

## Ten critical V6 blockers

- [ ] **V6-01 — Live scan progress and freeze-free UI.** Scheduler activity must reach durable SSE/UI state; reconnects reconcile; long tools show active task, elapsed time, completed/total tasks, and last activity without blocking the browser.
- [ ] **V6-02 — Cancellation, timeout, deadlock, and restart recovery.** Hanging tools, failed prerequisites, cancellation, and restart must end in bounded truthful states with no zombie subprocesses or infinite spinner.
- [ ] **V6-03 — Honest tool readiness and repair.** Every catalog entry must distinguish ready, credentials-required, dependency-missing, policy-blocked, unsupported, or deprecated; an unavailable tool cannot be launched as if ready.
- [ ] **V6-04 — Recon observations are not vulnerabilities.** Archive URLs, DNS/RDAP, crawled links, generic 200 responses, and fallback reconnaissance stay evidence/inventory unless a detector proves a security property violation.
- [ ] **V6-05 — Proof-graded finding lifecycle.** Enforce observation -> hypothesis -> candidate -> verified -> human-approved submission. Promotion requires current affected asset, reproducible expected/observed difference, controls, and supported impact.
- [ ] **V6-06 — Controlled vulnerable + patched validation fixtures.** At least five supported vulnerability classes must pass paired positive/negative lab fixtures with measured recall and false-positive rate.
- [ ] **V6-07 — Evidence custody and authorization.** Per-scan raw evidence, hashes, observation association, class-aware closure, redaction, encryption, and live authorization must remain intact through report/submission export.
- [ ] **V6-08 — Submission quality gate.** A draft needs affected asset, scope, reproducible steps, expected vs observed behavior, proof of impact, uncertainty/duplicate notes, remediation, and explicit human approval. CVSS stays unset without a defensible vector.
- [ ] **V6-09 — Observability and resource budgets.** Correlation IDs, bounded queues, backpressure, per-backend latency/error telemetry, rate/scope state, and CPU/memory responsiveness must survive high-event scans without losing terminal events.
- [ ] **V6-10 — Reproducible V6 release qualification.** Exact-commit CI, Windows installer/portable smoke, Linux smoke, migration/upgrade/rollback, offline/no-AI behavior, package hashes/SBOM, and manual UI acceptance must all pass.

## Mandatory release evidence

Before any checkbox above can be marked complete, attach its before/after reproduction, automated test or benchmark, negative control, relevant OS/backend coverage, and reviewer-visible artifact. A green unit-test run alone is not enough for a live-runtime gate.

The final V6 candidate must include both:

1. **Noise benchmark:** the synthetic equivalent of the supplied 587 informational HostGator-style report yields **0 submission-ready findings** while retaining reconnaissance evidence.
2. **Positive benchmark:** controlled vulnerable fixtures yield repeatable evidence-backed candidates and reviewable submission drafts; matched patched fixtures yield **0 verified findings** for the same checks.

## Release cut

- [ ] All V6-01 through V6-10 are checked with linked evidence.
- [ ] No release-blocking regression remains open.
- [ ] Full automated suite and V6 runtime/release gates are green on the exact candidate commit.
- [ ] Windows clean install/upgrade/uninstall and portable launch are verified.
- [ ] Limitations and unsupported tool/runtime combinations are documented.
- [ ] Only then set the release version, cut the V6 tag, and move PR #34 out of draft for final review.
