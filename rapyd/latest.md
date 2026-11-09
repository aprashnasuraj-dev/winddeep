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
