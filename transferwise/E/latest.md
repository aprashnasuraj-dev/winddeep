# TransferWise Lane E — Cross-repository and supply-chain integrity

Status: ENVIRONMENT_BLOCKED / NOT REPORTABLE ON CURRENT EVIDENCE (2026-11-09).

Objective: assess whether an unprivileged actor can cause a trusted Wise Terraform provider release to publish attacker-influenced artifacts.

Pinned source: transferwise/terraform-provider-awslambda@ddd26331a4f07a271a629dc3df7c57a8296a2aed. Inspected .github/workflows/release.yml, go.mod and README.md through the GitHub connector. The release workflow triggers on pushes of v* tags, checks out source, imports a configured GPG key, and invokes GoReleaser with GITHUB_TOKEN. No attacker-controlled tag creation or deployed Wise consumer was demonstrated. The module path is github.com/dedunu/terraform-provider-awslambda, so Wise-specific provenance/impact requires additional evidence.

Triage: (1) tag-to-signed-release boundary (selected); (2) dependency-to-provider-build boundary; (3) published-provider-to-Wise-infrastructure consumer boundary. All remain unproven; avoid recycling this commit without new evidence. Strongest counterexample: tag creation is restricted to trusted maintainers and release artifacts are consumed only with verified provenance.

Execution: actual local git ls-remote failed with 'Could not resolve host: github.com'. No isolated checkout, workspace doctor, target-runtime PoC, negative control or independent impact oracle executed. G0 scope yes but attacker entry unverified; G1 pinned source, shipped Wise consumer unverified; G2-G4 unmet. No severity, package, Library upload or chat ZIP.

Next decisive step: obtain an isolated checkout, run python scripts/audit/transferwise_workspace.py doctor --check, and establish an unprivileged tag/release input plus a Wise-specific consumer before any bounded local test. Retire if tag creation and publication are maintainer-only.
