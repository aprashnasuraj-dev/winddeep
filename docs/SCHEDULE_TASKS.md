# Windeep five hourly task contracts

Run times are in Asia/Kathmandu, each 12 minutes apart. GitHub Actions expressions run in UTC. These definitions are acceptance criteria, not evidence that missing harnesses already exist.

## 1 — Engine Capability Loop, :35 NPT (ChatGPT agent)
Step 0: if CI or the report flow is red, fix that first, add a regression test, open one PR, and stop for this run.
Step 1: read the latest measured benchmarks/history results and identify the bug class with the lowest recall on the authorized local labs (Juice Shop, DVWA, WebGoat, crAPI). If benchmark history is missing or stale, do not guess; open or update the benchmark-gap issue and stop.
Step 2: raise that class's detection with ONE capability upgrade: a new detector, improved tool-wrapper configuration, smarter payload/parameter discovery, an authorization-diff check, or a hypothesis-to-verification step. Prioritize high-payoff classes where supported by the labs: IDOR/BOLA, auth bypass, SSRF, JWT/session flaws, GraphQL/API discovery, JavaScript secret and endpoint harvesting, subdomain takeover, and race conditions.
Step 3: add local-lab regression tests proving it finds the target bug and does not worsen false positives. Re-run the relevant benchmark slice. Update the baseline only when measured recall improves and false-positive rate is no worse.
Output: exactly one focused PR with before/after recall and false-positive metrics for the selected class. Never weaken security controls or test public targets.

## 2 — Research Feed, :47 NPT (ChatGPT agent)
Study 3 recent public disclosed bug-bounty reports or technical writeups from reputable public sources. For each, extract the defensive detection idea: the observable signal that revealed the bug, its class, and relevant preconditions. Check whether Windeep could currently catch that signal through a detector, wrapper, correlation rule, or evidence path. For every material gap, add a ranked item to docs/BACKLOG.md with bug class, detection signal, safe local-lab test idea, expected payoff, estimated effort, and duplicate/false-positive risk. Re-rank by payoff versus effort while preserving P0/P1 operational blockers. Never reproduce attacks against public targets. If fewer than 3 suitable recent writeups can be verified, report the shortfall rather than inventing examples.

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
