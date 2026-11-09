# Rapyd · high-impact, evidence-first security audit
> Public Windeep coordination branch `rapyd`. As of **2026-11-09**, current authenticated Bugcrowd brief could not be read. Mirror listings are provisional; `config/programs/rapyd_bugcrowd.json` therefore disables ALL automated target-facing requests. This branch is READY for passive research, source analysis, local fixtures and reporting prep, **not** a license to actively probe the live financial network.

## Mission
Seek original, defensible **P0–P3** security issues, prioritizing measurable impact over volume. P0/P1 require extraordinary observed impact; a plausible idea never warrants a severity label. Each productive run selects ONE testable unique objective, executes within the currently verified authorization, includes an honest counterexample, and either progresses or retires the hypothesis.

## Authorization decision tree (hard gate)
1. Read the *current authenticated* [Rapyd Bugcrowd brief](https://bugcrowd.com/engagements/rapyd), changelog and participation rules. Record date/time, permission source and scope hash in **PRIVATE** records. Do not mark any gate verified based on scope trackers.
2. Treat `config/programs/rapyd_bugcrowd.json` as a **secondary snapshot** only. Explicit deny targets, third-party providers, CDN/redirect destinations and unknown domains override wildcard matches. Wildcard expansion is not blanket authorization.
3. Until official brief+participation+permitted testing methods are confirmed, perform **only offline/local lab work and passive reading of published pages and documentation**. No scripted requests to live Rapyd endpoints. No commercial payment interactions or tests with another person's account.
4. Even if authorized, obey rate/asset constraints from the official brief; target-facing active actions must be manually approved and limited to owned test identities. Never generate or replay payment/refund/payout requests on live endpoints, access others' data, test stolen credentials, attack third parties, automate support forms, or stress availability.
5. Any ambiguous asset, navigation to new hostname, DNS/CNAME transfer or changed brief => **STOP / SCOPE_REVIEW_REQUIRED**. Do not auto-enable testing by changing a local JSON flag.

## Evidence ladder: no promotion by rhetoric
| Gate | Required independently checkable evidence | Fail state |
|---|---|---|
| G0 authorization | Program brief verified, precise permitted target, attacker persona/owned account, safe test method | OUT_OF_SCOPE / POLICY_UNVERIFIED |
| G1 reachability | Target evidence on a Rapyd-owned asset, version/timestamp, entry and security boundary actually used | SOURCE_ONLY |
| G2 experiment | Safe positive and honest negative control in isolated fixture or permitted target; exact commands/results | NOT_EXECUTED / INSUFFICIENT |
| G3 effect | Independent oracle proving unauthorized state/data/privilege and quantifiable consequence; strongest fixing control | SPECULATIVE |
| G4 delivery | VRT P0–P3 justified by observed impact, duplicate check, private clean-room reproducibility, redacted report | REPORT_NOT_READY |

**Crucial:** a local mock can validate an *idea*, but never proves Rapyd's production system has the issue. `G2:MOCK` is NOT `G2:TARGET`; unverified live reachability prevents CONFIRMED. A report ZIP passing checksums is **not** exploit confirmation.

## Three-hypothesis novelty gate
Score three distinctly different, previously untested attack objectives: (attacker control × verified reachability × plausible harm × discriminatory experiment) ÷ verification cost; explain why winner beats the strongest alternative. Reject unsupported architecture guesses. Fingerprint = lane + exact approved asset + broad boundary + tester prerequisite + source snapshot. Compare all A–E ledgers and Bugcrowd known issues when accessible. Retire negatives; do not restart an identical case each hour. Reopen only with an explicit new asset/version, bypassing entry, fresh official policy, novel observed behavior or restored execution capability.

## Ownership and parallelism
A–E read this file, `rapyd/HANDOFF.md`, `rapyd/FAILURE_LESSONS.md`, `rapyd/REPORT_TEMPLATE.md`, program config, `rapyd/latest.md`, and all sanitized lane summaries. **Write only** `rapyd/<own lane>/PROBES.json` and `rapyd/<own lane>/latest.md`. Never touch `transferwise`, `main`, another lane, shared config/policy, workflows or target code during scheduled runs. Re-fetch branch head before each write, use non-force changes. Keep finding details, raw HTTP, POCs, accounts, secrets, screenshots and full report OUT of public git.

## Failure/stop conditions
- If GitHub network/DNS or shell access unavailable: record once with dated capability and stop repeating unchanged checkout attempts (retry no more than once daily unless environment changes). Connector read is NOT checkout or execution.
- If no newly testable objective passes policy/scope: `NO_NEW_VERIFIABLE_PROGRESS`, specific blocker, ONE unblock step. Do not manufacture fake P3s or report generic scan noise.
- No live attack because of a headline, severity target or historical public scope mirror.
- Never auto-submit. Stop active pursuit and write complete PRIVATE evidence upon actual independently reproduced reportable impact.

## Five lanes
A web build/front-end trust; B identity and tenant authorization; C input and server-side trust; D hosted checkout/verification/browser boundaries; E financial business invariants and webhook/idempotency. The lanes cover **Bugcrowd web/API assets**, not the previously used `transferwise/*` repository target.
