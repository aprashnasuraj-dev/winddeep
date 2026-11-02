# Ranked engineering backlog

Only one item per enhancement PR; max ~300 changed lines unless explicitly reviewed. Claim by linking a GitHub issue/PR before coding. Security gates are non-negotiable.

| Rank | Item | Acceptance | Status |
|---|---|---|---|
| P0 | Report generation regression / installed UI fan-out | Issue #22: closed P2 evidence exports, incomplete evidence fails closed, one window/icon in clean Windows installation | BLOCKED: reproduction pending |
| P1 | Scheduler reliability and crash resume | deterministic replay; no duplicated tool execution or lost encrypted checkpoint | queued |
| P1 | Tool-wrapper availability and portable resolution | missing integrations are marked unavailable, no unhandled FileNotFoundError | queued |
| P1 | Evidence-based deduplication | stable fingerprints, exact provenance preserved, no silent finding suppression | queued |
| P2 | Chain correlation | deterministic provenance for multi-step exploit hypothesis; no unsupported escalation | queued |
| P2 | Triage ranking | prioritize valid impact and reproducibility; benchmark against labeled local fixtures | queued |
| P2 | Duplicate-risk scoring | calibrated confidence and explicit risk in export; never claim external program uniqueness | queued |

Review P0 first. Use Docker-hosted OWASP Juice Shop, DVWA, WebGoat, and crAPI only after explicit local lab setup. No production targets.
