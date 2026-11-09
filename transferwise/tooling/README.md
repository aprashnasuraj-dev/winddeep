# TransferWise scheduled audit environment and evidence delivery

The five scheduled lanes A-E own only their respective transferwise/A-E/ folders.
No changes here authorize attacking live Wise systems or submitting a report.

## Environments

- GitHub connector: work only on aprashnasuraj-dev/winddeep branch transferwise;
  serialize branch writes using expected HEAD SHA. Read only authorized public
  transferwise repositories, excluding transferwise/pipelinewise.
- GitHub Actions: transferwise-readiness.yml checks the branch and file/evidence
  structure using Python 3.12 with contents:read, no secrets, and **no execution
  of arbitrary audit PoCs**. It runs on tooling/policy changes, not every hourly
  lane push. The existing transferwise-audit.yml remains the read-only scanner.
- Codespaces / VS Code Dev Containers: Python 3.12, git, GitHub CLI and pytest;
  no Wise credentials, privileged mounts, or blanket package installs. Install
  additional Java/Node/Terraform/Docker tools only for an identified target.
- Scheduled ChatGPT agents: connector/computer entitlement is managed on the
  automation side. A GitHub commit does NOT provision a computer or grant
  Library access. If execution or repository-write capability is unavailable,
  mark ENVIRONMENT_BLOCKED with the exact missing capability.

## Fresh checkout preflight

    git switch transferwise
    python scripts/audit/transferwise_workspace.py doctor --check
    python -m unittest discover -s tests -p test_transferwise_workspace.py -v

The doctor reports optional toolchains without treating them as prerequisites.

## Independently runnable finding package

Create the following only for a validated G0-G4 finding, inside the owning
lane directory (replace A and the finding slug with actual values):

    transferwise/A/submissions/finding-slug/
      MANIFEST.json
      REPORT.md
      REPRODUCE.md
      SCOPE.md
      IMPACT.md
      DUPLICATE_REVIEW.md
      ENVIRONMENT.md
      POC/repro.py
      EVIDENCE/executed.log
      EVIDENCE/CONTROL/negative.log

MANIFEST.example.json is deliberately set to CANDIDATE with all gates false.
Update the manifest with the exact in-scope repo, pinned 40-character commit,
justified P0-P2 (or exceptional P3), G0-G4 true, and independently observed
execution/control only AFTER actually reproducing them.

    python scripts/audit/transferwise_workspace.py pack --source transferwise/A/submissions/finding-slug --output transferwise/A/submissions/Wise_TransferWise_A_repo_finding_DATE.zip
    python scripts/audit/transferwise_workspace.py verify --zip transferwise/A/submissions/Wise_TransferWise_A_repo_finding_DATE.zip

The builder produces deterministic ZIP contents, MANIFEST file hashes and
SHA256SUMS; it rejects unsafe paths/symlinks, oversized files, incomplete
control evidence, unconfirmed claims and out-of-scope targets. Passing bundle
validation is not proof that a vulnerability exists: independently execute
the non-destructive PoC and control in an isolated fresh checkout.

## Two distinct delivery gates

1. Upload the sanitized verified ZIP into persistent ChatGPT Library at
   /Wise-TransferWise-Audit/<LANE>/ using an authorized Library-write tool;
   verify that the Library copy is readable (LIBRARY_VERIFIED).
2. Attach the ZIP or supply an actually accessible artifact link in the
   scheduled chat (CHAT_DELIVERED). Include exact reproduction commands,
   observed vs control result, impact and checksums in the chat report.

If either capability is unavailable, report DELIVERY_BLOCKED, preserve the
generated ZIP for a future retry and never invent a download URL. GitHub
Actions itself cannot directly write to the user's ChatGPT Library.

Only sanitize and distribute non-sensitive, legal, non-destructive fixtures.
The packaging checks are defense in depth, not a comprehensive secret scanner.
