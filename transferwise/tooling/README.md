# TransferWise scheduled-worker environment

This branch supports five existing hourly ChatGPT audit lanes. The repository is
PUBLIC: never commit unpublished vulnerability reports, PoCs, evidence, secrets
or ZIPs. Only non-sensitive lane coordination metadata belongs in git. The
authoritative private handoff and packaging contract is in
transferwise/HANDOFF.md and scripts/audit/transferwise_handoff.py.

## Wired tools and execution environments

- GitHub connector: read and write the winddeep transferwise branch using a
  checked current HEAD; never merge into main. Only public in-scope
  transferwise/* repositories are target sources; exclude pipelinewise.
- Codespaces / VS Code Dev Containers: Python 3.12, git, GitHub CLI and pytest
  are available after setup. No live target credentials or privileged mounts.
- GitHub Actions: transferwise-handoff.yml checks all five lanes, private-Git
  exclusions, bundle checksum/integrity tests and this environment preflight.
  It runs with contents:read, and neither executes genuine PoCs nor uploads
  private reports. Do not create another redundant readiness workflow.
- ChatGPT scheduled automations: must verify their own actual GitHub connector,
  shell/runtime and persistent Library access. A GitHub commit CANNOT attach a
  cloud computer or grant account-level permission to an automation.

## Worker preflight

    python scripts/audit/transferwise_workspace.py doctor --check

That command tests Python >=3.11 and git, reports optional gh, rg, Docker,
Node, Java and Terraform availability, and invokes the existing fail-closed
repo-check gate. Install optional toolchains only for a pinned target needing
that runtime. If the agent lacks local execution access, record
ENVIRONMENT_BLOCKED rather than inventing command results.

## Canonical portable ZIP packaging

After a finding independently passes G0-G4, prepare a sanitized package in a
PRIVATE location outside tracked Git:

    /private/finding/
      REPORT.md
      REPRODUCE.md
      SCOPE.md
      IMPACT.md
      DUPLICATE_REVIEW.md
      ENVIRONMENT.md
      POC/reproduce.py
      EVIDENCE/run.log
      EVIDENCE/CONTROL/negative.log

Then use the pre-existing builder, which produces MANIFEST.json and SHA256SUMS:

    python scripts/audit/transferwise_handoff.py pack --source /private/finding --output /private/Wise_TransferWise_A_repo_finding_DATE.zip --lane A --repo transferwise/example --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --severity P2
    python scripts/audit/transferwise_handoff.py verify /private/Wise_TransferWise_A_repo_finding_DATE.zip

The helper checks STRUCTURE ONLY. It does not attest the PoC executed or
certify a vulnerability. Execute bounded reproduction and negative control
independently in a fresh isolated environment; preserve exact results,
limitations and version pins. The ZIP remains private and untracked.

Deliver the verified ZIP using an authorized persistent ChatGPT Library tool
under /Wise-TransferWise-Audit/<LANE>/; separately provide an accessible
attachment/link in the scheduled chat. Verify LIBRARY_VERIFIED and
CHAT_DELIVERED independently. If either operation cannot be completed,
mark DELIVERY_BLOCKED, retain the private ZIP and do not invent links.
