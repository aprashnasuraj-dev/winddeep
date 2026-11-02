# Windeep release readiness (human-approved only)

- [ ] All P0/P1 issues closed with verified PRs, including issue #22.
- [ ] VERSION, package metadata and CHANGELOG match the proposed semantic version.
- [ ] All required tests/coverage pass on the candidate SHA (Python 3.11, windows-latest).
- [ ] Three consecutive **actual** green nightly Docker-lab benchmark histories, matching a pinned fixture snapshot.
- [ ] Recall/false positives, runtime and evidence completeness have no regression >5% against measured baseline.
- [ ] All eligible findings export reports: 100% report success; all P2 integrity and authorization gates remain enforced.
- [ ] Report rubric average >=8/10, no item below 8 requiring unreviewed changes; 0 plaintext secrets in outputs.
- [ ] One instance/window and no duplicated Python UI icons in a clean Windows VM.
- [ ] PyInstaller installer/portable artifacts built from the exact candidate commit.
- [ ] Inno Setup clean Windows install, launch, upgrade and uninstall audit passed.
- [ ] SHA256SUMS and SBOM generated and validated against exact artifacts.
- [ ] RC tag never triggers public publishing; draft release and Release Ready issue only after gates pass.
- [ ] Human explicitly approves final production tag and release publication.

GitHub Actions scheduled runs on the default branch. PR workflow files are **not active until merged**. GitHub Actions cron is UTC; NPT=UTC+05:45. The 3 scheduled jobs below must fail closed while their benchmark adapters are missing. Never fabricate history or green status.
