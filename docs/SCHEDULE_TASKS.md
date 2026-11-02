# Windeep five hourly task contracts

Run times are in Asia/Kathmandu, each 12 minutes apart. GitHub Actions expressions run in UTC. These definitions are acceptance criteria, not evidence that missing harnesses already exist.

## 1 — Fix Loop, :35 NPT (ChatGPT agent)
Run pytest and check CI and open issues/PRs. Pick the top failure, with report generation first. Reproduce it, find the root cause, fix it, add a regression test, and open a PR. If nothing is failing, run the report flow end to end on a lab scan and report the result. Diagnose repeated Python UI icons after reporting; do not confuse missing evidence with a bug or bypass secure gates.

## 2 — Engine Enhancement, :47 NPT (ChatGPT agent)
Take the top item from docs/BACKLOG.md (scheduler reliability, tool-wrapper coverage, dedup, chain correlation, triage ranking, duplicate-risk scoring). Implement it in under 300 changed lines with tests and open one PR. If the backlog is empty, audit the engine and add five ranked items with reasons.

## 3 — Candidate Testing, :59 NPT (GitHub Actions, UTC cron `14 * * * *`)
Run full scans against explicitly authorized Docker local labs. Record recall vs the known-vulnerability list, false-positive rate, report success rate (must be 100% of eligible findings), evidence-bundle completeness, and runtime. Compare with benchmarks/baseline.json, commit measured results to benchmarks/history/ through a dedicated PR (not main), and open an issue for any regression over 5%. Never fabricate a baseline, never claim a missing harness passed, and include machine-readable provenance/fixture snapshot for comparability.

## 4 — Report Quality Audit, :11 NPT (GitHub Actions, UTC cron `26 * * * *`)
Generate reports for the benchmark findings and score each 0–10 on title, impact, step-by-step reproduction, correct CVSS 3.1 vector, evidence, secrets redaction, brevity, and duplicate-risk note. Check exported Markdown/HTML/JSON/evidence bundles for leaked secrets. Fix templates scoring below 8 and open a scoped feature PR with before/after scores; maintain provenance and guards. Do not claim a subjective score without a deterministic scoring rubric and reviewed fixtures.

## 5 — Release Gate, :23 NPT (GitHub Actions, UTC cron `38 * * * *`)
Build release candidate vX.Y.Z-rc.N: bump semver, update CHANGELOG, run Windows PyInstaller/Inno Setup build, clean-VM install/uninstall audit, generate SHA256SUMS and SBOM. READY only with three consecutive real green nightly benchmarks, no open P0/P1 issues, no metric regressions, 100% report success, complete evidence, zero secret leaks and installer audit passing. If READY, create a draft GitHub Release and a Release Ready issue. Never auto-publish final release; final version tag and release require human approval. If any prerequisite missing, mark NOT READY; do not mint release tags or create false-ready artifacts.

## Universal operating rules
- Repository aprashnasuraj-dev/winddeep. Never push main: each code change and benchmark history commit uses a branch and PR. Check existing PR/issue claims first.
- Each change includes relevant tests, VERSION/CHANGELOG synchronization where appropriate; release-candidate versioning belongs solely to Release Gate to avoid collision.
- Never weaken scope, explicit consent, scan authorization, preflight, redaction, encryption, artifact integrity or audit. Network scans run only against owned local lab containers (Juice Shop, DVWA, WebGoat, crAPI).
- End every run with status: exact commands/checks, pass/fail, changed files and PR, blockers, next action. No asynchronous claims without recorded evidence.
- CI definitions may lack operational benchmark/rubric/release adapters: they fail closed until implemented. Scheduled workflows become operational only after merge and required permissions/actions are configured.
