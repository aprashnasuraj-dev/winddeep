# Wise scheduled workers: secure Git-to-ChatGPT handoff

**Important:** The `winddeep` repository is PUBLIC. The `transferwise` branch is a shared coordination/control plane, not a vulnerability disclosure repository. Never commit unreported vulnerability details, exploit reproduction, full reports, sensitive raw logs, credentials, unpublished PoCs, or ZIP evidence bundles.

## Five lane workspaces

| Worker | Owns | Primary audit focus |
| --- | --- | --- |
| A | `transferwise/A/` | CI/CD and repository trust |
| B | `transferwise/B/` | Authentication, authorization, signing |
| C | `transferwise/C/` | Unsafe data flow and code execution |
| D | `transferwise/D/` | Infrastructure and deployment integrity |
| E | `transferwise/E/` | Cross-repository and supply-chain trust |

Each scheduled worker reads `transferwise/AUDIT_SYSTEM.md`, `transferwise/HANDOFF.md`, `config/programs/transferwise_github.json`, `transferwise/latest.md`, and its own `PROBES.json` and `latest.md`. Only sanitize-and-commit **lane-owned operational metadata** (not exploitable unpublished findings). Shared policies and workflow files remain read-only during scheduled research. Never merge into `main`.

Every run should score at least three distinct **in-scope** hypotheses for attacker control, realistic Wise-specific impact, reachability, independent falsification and verification cost. Pursue a decisive test on the highest-value untested hypothesis; retire negatives quickly. This does not relax G0–G4, no-live-exploitation rules, or the explicit `transferwise/pipelinewise` exclusion.

Concurrent runs: re-fetch branch HEAD immediately before modifying your own lane, reconcile if HEAD changed, use non-force updates, and never overwrite another worker's results or revert shared files. Do not rotate schedule timings.

## Required private handoff after G0–G4

1. In a **local/private, untracked workspace**, assemble `REPORT.md`, `REPRODUCE.md`, `SCOPE.md`, `IMPACT.md`, `DUPLICATE_REVIEW.md`, `ENVIRONMENT.md`, `POC/` scripts/fixtures, observed `EVIDENCE/` artifacts and honest negative `EVIDENCE/CONTROL/` artifacts.
2. Pin the exact upstream `transferwise/<repo>@<40-digit-sha>`. Include prerequisites, commands, expected and observed output, clean environment, realistic security effect, strongest counterexample, constraints, and duplicate review. Sanitize names, secrets, personal data, and private paths.
3. Build a portable ZIP with the offline helper (below). It generates a `MANIFEST.json` and `SHA256SUMS` and rejects missing evidence, unsafe paths, symlinks, duplicates, oversize, and checksum tampering.
4. **Independently execute the reproduction from a fresh extraction and clean environment**, with both positive and negative controls. Structural verification is NOT an executed PoC or a security finding. Do not test live Wise systems.
5. Upload and verify ZIP readability in the user's persistent ChatGPT Library at `/Wise-TransferWise-Audit/<LANE>/`. Separately attach/provide a reachable artifact reference in the scheduled ChatGPT run conversation when supported.
6. Mark the two statuses independently: `LIBRARY_VERIFIED` and `CHAT_DELIVERED`. If either operation fails, report the exact blocker as `DELIVERY_BLOCKED`, preserve the private artifact, and retry. Never claim upload/attachment success without verification; never auto-submit to Bugcrowd.

Example (from a trusted local or private task environment, **not** GitHub Actions):

```bash
python scripts/audit/transferwise_handoff.py pack \
  --source /private/wise-finding \
  --output /private/Wise_TransferWise_A_example_finding_2026-11-09.zip \
  --lane A --repo transferwise/example \
  --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --severity P2

python scripts/audit/transferwise_handoff.py verify \
  /private/Wise_TransferWise_A_example_finding_2026-11-09.zip
```

The ZIP helper checks structure and SHA256 integrity; it explicitly labels the result `STRUCTURE_ONLY_NOT_CONFIRMED`. A passing check **never** means the finding is confirmed or that the PoC executed. The scheduled agent must verify G0–G4 separately and present the actual command/output/control in chat.

## Git readiness and CI

The lightweight `transferwise-handoff.yml` GitHub Actions workflow runs on pull requests into `transferwise` and qualifying changes to `transferwise`. It verifies five-lane manifests, policy scope, absence of tracked private evidence, and synthetic package tests. No real finding or private ZIP is uploaded to public CI.

Keep `transferwise/<LANE>/latest.md` short: objective, repo@SHA, safe gate state, non-sensitive outcome, and next decisive test. Do not commit the evidence itself. The private material belongs in the private Library and scheduled chat delivery.
