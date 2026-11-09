# Rapyd · five-lane audit coordination and private handoff

**Public branch:** `aprashnasuraj-dev/winddeep@rapyd`. This git branch is only a safe operational control plane. The `transferwise` branch and `main` are outside this mission, untouched.

## Scheduled lane ownership
| Lane | Exclusive public write paths | Specialized attack boundary |
|---|---|---|
| A | `rapyd/A/PROBES.json`, `rapyd/A/latest.md` | Asset-origin deployment, frontend trust, source/build artifacts |
| B | `rapyd/B/PROBES.json`, `rapyd/B/latest.md` | AuthN/AuthZ, merchant tenancy, credential and signing integrity |
| C | `rapyd/C/PROBES.json`, `rapyd/C/latest.md` | Backend data flows, input parsing and code/data injection |
| D | `rapyd/D/PROBES.json`, `rapyd/D/latest.md` | Hosted checkout, verification, redirects, browser isolation |
| E | `rapyd/E/PROBES.json`, `rapyd/E/latest.md` | Webhooks, state machines, event order, idempotency and finances |

All workers read common immutable policies. A–E never overwrite the same files. Before updating a file, read its current blob SHA and branch head. Race => reread and reconcile; **never force push**. Report only sanitized fingerprints/learning outcomes in public.

## Private finding package (only after G0–G4)
A confidential workspace **outside git** holds:
- `REPORT.md`: title, category/CWE, program asset, authorization evidence, severity+VRT reasoning, precise consequence
- `REPRODUCE.md`: environment, exact permitted requests/commands, expected vs observed positive result, negative control, redaction
- `SCOPE.md`: official brief version and program rule snapshot; target, user-owned personas and excluded assets checked
- `IMPACT.md`: attacker preconditions, affected permissions/data/value, measured scope, strongest mitigating counterexample
- `DUPLICATE_REVIEW.md`: prior attempts and known issues checked, scope changes, differentiating behavior
- `ENVIRONMENT.md`: real execution context, product version, evidence provenance, limitations and dependencies
- `POC/`, `EVIDENCE/`, `EVIDENCE/CONTROL/`: minimal local fixtures and redacted independently observed results

Before packaging, freshly reproduce the violation and negative control in an isolated *authorized* environment and compare with a second oracle. Distinguish testing an offline model from target execution. Never include another merchant's data, credentials, payment details or secret tokens. Do not share unreported findings publicly.

## Delivery truth table
- `CONFIRMED_PRIVATE`: G0–G4 met with actual independently observed target evidence, not merely scanner reports.
- `PACKAGE_VERIFIED`: structure/checksum of ZIP validated (different claim from exploit verification).
- `LIBRARY_VERIFIED`: uploaded to the private `/Rapyd-Audit/<LANE>/` location **and read back**.
- `CHAT_DELIVERED`: reachable private attachment in ChatGPT confirmed.
- `DELIVERY_BLOCKED`: any delivery not available; say what failed and keep artifacts private.
- `SUBMITTED`: only when user manually submits through official Bugcrowd and provides acknowledgement; never infer from a prepared report.

Do not invent ZIP paths, hashes, uploads, reproducibility, reward amounts, confirmed P0/P1 or program permission. Use the common `rapyd/REPORT_TEMPLATE.md` for a complete Bugcrowd-ready report.

## Run outputs
Five-to-eight concise lines: NEW/REPEATED, selected target+snapshot, scope/participation state, owned test persona, hypothesis and strongest guard, experiment+honest control (or NOT EXECUTED), G0–G4, verdict+artifact delivery status, new data and next decisive action. Zero meaningful progress must be labeled honestly. Scheduled research is **not** live target scanning by default.
