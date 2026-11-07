# Electroneum Audit Target Manifest

> **2026-11-07 execution clarification:** The canonical bootstrap below now runs **inside the GitHub Actions runner**, not inside the hourly research agent's local environment. The agents must inspect source through the GitHub connector and execute certified target tests via `.github/workflows/electroneum-adversarial-matrix.yml` or another approved bounded Actions job. Do not use local Git/DNS failures as a work-blocker or relax the immutable tree identity checks. See `shared/RESEARCH_ARCHITECTURE.md`.


- Canonical certified source path: `vendor/electroneum-sc/`.
- Immutable Windeep source commit: `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`.
- Canonical Git subtree SHA: `de7f3c75a2db7e87a89918f1257820703d5b731e`.
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

The bootstrap verifies the schema-2 certificate, requires the immutable Windeep source commit object, checks both that commit and `HEAD:vendor/electroneum-sc` resolve to the certified subtree SHA, rejects dirty source checkouts, materializes bytes from the immutable source commit into a fresh read-only scratch directory, and exports `WINDEEP_ETN_SOURCE`.

Required runtime identities:

```text
WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT=7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0
WINDEEP_ETN_SOURCE_TREE_SHA=de7f3c75a2db7e87a89918f1257820703d5b731e
WINDEEP_ETN_PINNED_SOURCE_COMMIT=3aeb14db0d6384243302f3a025bdff904dc28bf6
WINDEEP_ETN_ARCHIVE_SHA256=3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b
```

The Git tree SHA is the everyday canonical target identity. The archive hash is retained as provenance evidence, not recomputed per worker run. A chat attachment is never required, and workers must never substitute a differently obtained upstream tree.


## Certification repair note

The earlier Windeep source commit `21162f549d95e4117bb954426cba436262ef4b2f` / tree `3571f9f8e31ca3f2e85c2a32acbc002bc3a177cc` is superseded and MUST NOT be used. Its enclosing Git add respected nested upstream ignore rules and omitted 77 upstream-tracked blobs. The repaired immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` force-staged the extracted certified source and was verified against `electroneum/electroneum-sc@3aeb14db0d6384243302f3a025bdff904dc28bf6`: 1,921 upstream blobs, 1,921 Windeep blobs, zero missing, zero extra, zero blob-SHA mismatches. The two upstream gitlinks are recorded in the certificate but are not materialized into the extracted audit target.


## Migration gate

- Provenance chain: `reports/electroneum/SOURCE_PROVENANCE.json`.
- Required gate before A-E worker switch: `.github/workflows/electroneum-pinned-source-gate.yml`.
- The gate compares the historical ZIP extraction with the pinned Git-object materialization path-for-path and byte-for-byte, then exercises all required negative controls.
