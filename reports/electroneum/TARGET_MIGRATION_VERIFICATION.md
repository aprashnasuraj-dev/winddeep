# Electroneum Certified-Tree Migration Verification

Status: **PASSED — worker switchover gate satisfied**

## Canonical source

- Repaired immutable Windeep source commit: `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`
- Certified Git subtree SHA: `de7f3c75a2db7e87a89918f1257820703d5b731e`
- Certificate commit: `50a774ed3d1103e84ca6148be3af53994cadf746`
- Runtime/test gate commit: `d3c398570dccbf6f8f32b76f3acb60e3581ba7d3`
- Upstream source: `electroneum/electroneum-sc@3aeb14db0d6384243302f3a025bdff904dc28bf6`
- Upstream root tree: `bc45332f06c9e4db462951d80243b462982b3f04`
- Provenance ZIP SHA-256: `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`

## Superseded certification

The earlier Windeep source commit `21162f549d95e4117bb954426cba436262ef4b2f` / tree `3571f9f8e31ca3f2e85c2a32acbc002bc3a177cc` is invalid for audit use and is superseded.

Root cause: the certification commit used a normal `git add` over the extracted upstream source. Nested upstream ignore rules caused 77 upstream-tracked files to be omitted from the Windeep vendor tree. The missing paths included security-relevant areas such as `core/state/*`, `core/vm/runtime/*`, `internal/build/*`, and build/test files.

Repair: certification now force-stages the canonical extracted source and verifies tracked path/blob parity against the immutable upstream commit before publishing the certificate.

## Source parity proof

Direct Git-object comparison after repair:

- Upstream tracked blobs: **1,921**
- Windeep certified blobs: **1,921**
- Missing paths: **0**
- Extra paths: **0**
- Blob-SHA mismatches: **0**
- Windeep symlinks: **0**
- Windeep materialized gitlinks: **0**
- Upstream gitlinks recorded separately in the certificate: **2**

## Bootstrap regression and migration-equivalence gate

GitHub Actions run: `41612610208`
Job: `bootstrap-regression`
Result: **success**

Observed test results:

1. **Valid certified source** — PASS. Bootstrap exported source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` and tree `de7f3c75a2db7e87a89918f1257820703d5b731e`.
2. **Wrong tree SHA** — PASS; failed closed with exit code **24**.
3. **Modified checkout** — PASS; dirty worktree bytes did not contaminate the fresh Git-object materialization.
4. **Missing Git tree object** — PASS; failed closed with exit code **23**.
5. **Malicious symlink** — PASS; mutable-worktree symlink did not contaminate materialization, and a committed symlink fixture changed the subtree identity and was rejected with exit code **24**.
6. **Legacy ZIP vs certified Git tree equivalence** — PASS; **1,921/1,921 file paths and SHA-256 file contents matched exactly**.

## Switchover decision

The equivalence gate is satisfied. Continuous Workers A-E may now use only:

```bash
source tools/electroneum_target_bootstrap.sh
```

Routine worker runs must not re-extract or re-hash the historical ZIP and must not fetch a substitute upstream tree. The ZIP remains provenance evidence; the certified Git subtree is the everyday target identity.
