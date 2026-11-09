# Rapyd Bugcrowd audit · branch status (2026-11-09)

- **Branch:** `aprashnasuraj-dev/winddeep@rapyd`, initialized independently from the hardened `transferwise` audit baseline. **No merge** to `main`; the `transferwise` mission remains on its own branch.
- **Program:** https://bugcrowd.com/engagements/rapyd
- **Scope source:** 2026-08-12 mirror snapshot: 10 reported eligible and 11 explicitly excluded target rules; see `config/programs/rapyd_bugcrowd.json`.
- **Policy status:** `SECONDARY_ONLY_UNVERIFIED`. Official authenticated Bugcrowd brief inaccessible from this run; participation, exact testing methods and current reward policy not attested. **Automated live targeting disabled.**
- **Permitted now:** passive public information review, source/architecture triangulation without probing, local fixtures, lab experiments, novel hypothesis triage and private report preparation.
- **Forbidden:** network probing of Rapyd until policy and individual authorization are verified; all out-of-scope assets, third-party redirects, support automation, other merchants' data, real payouts/refunds/payments, brute force, stress/DoS, leaked-credential checks and auto-submit.
- **Severity priority:** P0–P3 only on observed evidence, with G0–G4 gates and independent negative control.
- **Shared policy:** `rapyd/AUDIT_SYSTEM.md`, `rapyd/HANDOFF.md`, `rapyd/FAILURE_LESSONS.md`, `rapyd/REPORT_TEMPLATE.md`.
- **Public metadata:** independent A–E lane ledgers/short reports; full vulnerabilities and PoCs remain in private handoff only.
- **Previous failure corrections:** no irrelevant unshipped source assumptions, no hourly repetition of DNS/environment blocker, no source-only confirmation, no fictitious reports.
- **Next unblock:** a verified copy of the current official brief and authorized researcher status would permit a *separate*, explicitly consented update to testing authorization. The saved schedule itself does not confer permission.

## Verified implementation readiness · 2026-11-09

- Scope classifier: `python scripts/audit/rapyd_scope.py --self-test` (offline only).
- Runtime + public-evidence safeguards: `python scripts/audit/rapyd_workspace.py doctor --check` and `python scripts/audit/rapyd_handoff.py repo-check`.
- Synthetic package structure, checksum, private-artifact exclusions and explicit-deny scope behavior are tested by `tests/test_rapyd_scope.py` and `tests/test_rapyd_handoff.py`.
- GitHub Actions: `.github/workflows/rapyd-readiness.yml`; first verified passing exact head: `f7e0a94ec67a83e9bc5457cb650c2af559150f8e`, run `42620330401`, **11/11 offline tests passed**.
- Existing five hourly automations were retargeted IN PLACE to Rapyd and independently verified enabled: A :08, B :20, C :32, D :44, E :56 (Asia/Kathmandu). Target-live actions remain disabled in the baseline because official brief+participation are not verified.
- `scripts/audit/rapyd_handoff.py pack` accepts `--asset`, `--snapshot-sha256`, `--priority`, `--policy-reviewed`; resulting ZIP passes structural checks only, NOT a confirmed exploit or proof of Bugcrowd eligibility.
- **Findings at setup:** zero confirmed Rapyd vulnerabilities; no actual target testing, no private reports submitted, no reward assertions.
