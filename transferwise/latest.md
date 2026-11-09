# TransferWise GitHub audit status

- Branch: `transferwise`
- High-impact control-plane commit verified: `fae8e9dd6e594604ff5083763f3ba2b258fe7193`
- Verified GitHub Actions run: `42575098218` — **32/32 checks SUCCESS**
- Scope: `github.com/transferwise/*`
- Explicit exclusion: `transferwise/pipelinewise`
- Public repositories inventoried after exclusion: **152**
- Baseline prioritized source-audit batch: **30 repositories**
- Known already-reported issues: **5**; fingerprints unavailable, so every candidate requires duplicate review
- Automated credential login validation: **disabled**
- Network exploitation / destructive testing: **disabled**
- Automatic submission: **disabled**

## High-impact operating policy

Scheduled research is now **P0/P1/P2-first**. An exceptional P3 may be completed only when the exploit path, security-boundary violation, reproducible proof and Wise-specific impact are already concrete. Generic P3 hunting and all P4/P5 work are excluded.

A reportable result must pass G0-G4 from `transferwise/AUDIT_SYSTEM.md`: exact scope/attacker entry, relevant pinned commit/trust boundary, bounded PoC plus honest control, independent Wise-specific security effect, then defensible severity + duplicate review + sanitized reproduction.

Scanner output, code smells, dependency CVEs, placeholder/sample secrets, public leaked-credential lists, and third-party-only vulnerabilities cannot self-promote into findings.

## Parallel lanes

| Lane | Mission | Workspace |
|---|---|---|
| A | CI/CD, PR/fork trust, tokens, releases, signing, packages, repository takeover | `transferwise/A/` |
| B | Authentication, authorization, OAuth/session/token/signature/idempotency | `transferwise/B/` |
| C | Command/build/template execution, deserialization, parser/injection data flow | `transferwise/C/` |
| D | Wise-specific IaC/cloud/deployment trust and privilege boundaries | `transferwise/D/` |
| E | Cross-repository build/release/artifact/package supply-chain integrity | `transferwise/E/` |

Each lane owns an independent `PROBES.json` and `latest.md`, with at most three active hypotheses. Shared files are read-only during scheduled hunting to avoid A-E collisions.

## Scheduled workers

The five pre-existing ETN automation IDs were remapped in place rather than duplicated. They are enabled on their existing staggered hourly schedule in Asia/Kathmandu:

- A — :08
- B — :20
- C — :32
- D — :44
- E — :56

No Electroneum mission remains in those five task prompts.
