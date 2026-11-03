# Electroneum Audit Target Manifest

- Canonical certified source path: `vendor/electroneum-sc/`.
- Immutable Windeep source commit: `21162f549d95e4117bb954426cba436262ef4b2f`.
- Canonical Git subtree SHA: `3571f9f8e31ca3f2e85c2a32acbc002bc3a177cc`.
- Pinned upstream Electroneum source identity: `electroneum/electroneum-sc@3aeb14db0d6384243302f3a025bdff904dc28bf6`.
- One-time provenance archive SHA-256: `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.
- One-time archive Git blob: `581c984e3e0d6451bc6273c19edf1bdb78dfed0a`.
- Certified file count: 1,921 (sanity metadata only; not the identity check).
- Working branch: `aprashnasuraj-dev/winddeep:electroneum-sc-master-audit`.
- Machine-readable certificate: `reports/electroneum/TARGET_CERTIFICATE.json`.

The archive was used once to establish provenance and was compared against the pinned upstream commit before the canonical source tree was committed. Continuous Workers A-E MUST NOT re-extract or re-hash the ZIP on every run.

For every A-E audit, synchronize the latest audit branch and run:

```bash
source tools/electroneum_target_bootstrap.sh
```

The bootstrap verifies that `HEAD:vendor/electroneum-sc` resolves to the certified subtree SHA, materializes those Git-object bytes into a fresh scratch directory, makes that materialization read-only, and exports `WINDEEP_ETN_SOURCE`.

Required runtime identities:

```text
WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT=21162f549d95e4117bb954426cba436262ef4b2f
WINDEEP_ETN_SOURCE_TREE_SHA=3571f9f8e31ca3f2e85c2a32acbc002bc3a177cc
WINDEEP_ETN_PINNED_SOURCE_COMMIT=3aeb14db0d6384243302f3a025bdff904dc28bf6
WINDEEP_ETN_ARCHIVE_SHA256=3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b
```

The Git tree SHA is the everyday canonical target identity. The archive hash is retained as provenance evidence, not recomputed per worker run. A chat attachment is never required, and workers must never substitute a differently obtained upstream tree.
