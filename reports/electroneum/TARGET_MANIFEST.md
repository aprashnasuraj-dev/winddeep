# Electroneum Audit Target Manifest

- Canonical source archive: `electroneum-sc-master.zip`, stored in Windeep Git commit `7d93d2435750ef258445f4a57142bb7b43a644f4`.
- Required archive SHA-256: `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.
- Pinned Electroneum source identity: `3aeb14db0d6384243302f3a025bdff904dc28bf6`.
- Working branch: `aprashnasuraj-dev/winddeep:electroneum-sc-master-audit`.
- Verified extraction: GitHub Actions run `41603929945` established the archive hash and extracted 1,921 files.

For every A–E audit, start from a full Windeep Git checkout and run `source tools/electroneum_target_bootstrap.sh`. The script fetches the canonical ZIP from Git history, checks its exact SHA-256, extracts it into a local scratch directory, and exports `WINDEEP_ETN_SOURCE` as the only permitted audit target. Its machine-readable outputs include `WINDEEP_ETN_ARCHIVE_SHA256` and `WINDEEP_ETN_PINNED_SOURCE_COMMIT`.

A conversation attachment is **not** required. Never substitute a differently obtained Electroneum source tree. An actual inaccessible Git object, checksum mismatch, corrupt ZIP, or missing local extraction dependency must be reported specifically as a bootstrap failure; an absent chat attachment is not a blocker.
