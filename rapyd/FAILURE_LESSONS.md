# Rapyd reboot: lessons from earlier audit attempts (2026-11-09)
These are observed workflow failure modes, NOT claims that any company was vulnerable.

## Failure mode 1 — relevance/impact inversion
The earlier source-code audit repeatedly surfaced reusable libraries, samples, IaC defaults and source primitives without proving that a shipped, attacker-reachable business/security boundary was affected. This produced activity but no reportable vulnerability.
**Correction:** Reject at G0/G1 unless the exact Rapyd-owned, in-program asset and attacker entry are evidenced. Bugcrowd's Rapyd program is an **asset** scope; unrelated `github.com/rapyd/*` or other repositories are NOT authorized targets just because Rapyd published them. A scary primitive, CDN script, generic CVE, guessed internal endpoint or a test/mock alone is never a finding.

## Failure mode 2 — environment failure + hourly repetition
Prior workers hit `Could not resolve host: github.com` and could not run the mandatory checkout/doctor/test. They then revisited similar theories repeatedly. Tool reads, code snippets and formatting tests were at risk of being mistaken for execution.
**Correction:** One preflight/capability matrix per run, dated blocker ledger with retry no more than once per 24h without a changed environment; prefer independent offline fixtures only where legitimate; never call `G2:TARGET` or `CONFIRMED` without actual reproduction. Retire exact hypotheses; keep max three active leads and strong cross-lane dedupe.

## Additional failure prevention
- **Scope drift:** live official brief unavailable; third-party mirror is informational. Current policy is POLICY_UNVERIFIED, network audit disabled. Updating a local configuration value cannot grant authorization.
- **Missing reports:** report only after positive and negative evidence, independent impact oracle, strongest counterexample, duplicate review, and a private reproducible package. `PACKAGED` ≠ `CONFIRMED`.
- **Exposure:** Windeep repository is public. Full writeups, requests, PoCs, logs, secrets, test identities and unreleased details never enter it. Public git stores only muted status and fingerprints.
- **Selection bias:** # of possible P0/P1 bug ideas is not bug count. P0–P3 is a search priority, not promised severity. Falsified candidates and effective controls are useful outcomes.
- **Worker collisions:** A–E exclusively write own two files. Prompt updates do not overwrite other lanes or alter `main`.
- **False automation claims:** Separate schedule-enabled, execution-environment-accessible, target-policy-authorized, test-executed, report-packaged and submission-delivered statuses; verify each independently.

## Readiness checklist
1. Scope mirror recorded and explicit denies enforced.
2. Official program policy and researcher access: **not yet verified**.
3. Branch, five lane files, read-only policy: ready for passive/local research.
4. Live active testing: **disabled** pending verification.
5. Each run must produce a novel falsifiable hypothesis or stop without filler.
