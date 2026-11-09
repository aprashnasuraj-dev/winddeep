# TransferWise Lane E — Cross-repository and supply-chain integrity

Status: ENVIRONMENT_BLOCKED / CANDIDATE ONLY (2026-11-09)

Objective: test whether untrusted GitHub comment or issue text can trigger a privileged cross-repository AI-agent workflow through a reusable workflow trust boundary.

Pinned public source: `transferwise/.github@787be76f0a5211a2e7c6a4080fe82931c084fa2d`, `workflow-templates/call-ci-ai-agents.yml`. The template includes issue/comment/review event triggers, a literal command gate, and a cross-repository reusable-workflow call with `secrets: inherit`. These source observations alone do not establish deployment, attacker reachability, or exploitability.

Triage (relative, qualitative): (1) issue/comment-to-privileged reusable workflow; (2) cross-repository workflow ref integrity; (3) artifact provenance-to-privileged consumer. Selected (1) as the new untested hypothesis. Strongest counterexample: only trusted maintainers can invoke the actual deployed consumer, or the reusable workflow rejects untrusted events and does not expose privileges.

Decisive boundary check: public retrieval of `transferwise/claude-code-action/.github/workflows/reusable-workflow-ci-ai-agents.yaml@main` returned 404; a repository search also failed with 422. No accessible deployed consumer or privilege effect was verified. Local `git ls-remote` of the audit checkout failed on DNS resolution of github.com; workspace doctor and target-runtime positive/negative tests were not run.

G0: in-scope producer identified, realistic unprivileged trigger not verified. G1: exact public source pinned, consumer/relevance unverified. G2-G4: not met. No severity, no submission, no private package, no Library/chat delivery.

Next decisive test: obtain an authorized isolated checkout and a verifiable public deployed consumer, run `python scripts/audit/transferwise_workspace.py doctor --check`, then independently test both authorized and untrusted comment events in safe fixtures. Retire if invocation is restricted or consumer enforces actor trust. Never run against live Wise infrastructure.
