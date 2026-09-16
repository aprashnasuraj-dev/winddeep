# Windeep v3.0.0 release checklist

## Release identity and frozen contracts

- [ ] `VERSION` is exactly `3.0.0`.
- [ ] `CHANGELOG.md` contains `## [3.0.0]`, P0–P8 phase map, V3-A/V3-B/V3-C summary, breaking changes and migration notes.
- [ ] Frozen public contracts remain: `windeep.sse.v1`, `windeep.har-extension.v1`, `windeep.evidence-bundle.v1`, `windeep.artifact.v1`, `windeep.report.v1`, `windeep.verification.v1`.
- [ ] `0030_v3_release.py` applies/reverts cleanly; down never drops or rewrites evidence-bearing tables.

## Security invariants

- [ ] Preflight remains fail-closed for target/tool activity and v3 evidence/report reads reuse stored scan authorization.
- [ ] Loopback-only dashboard and encrypted-at-rest stores remain unchanged.
- [ ] No plaintext scan temp survives cleanup.
- [ ] C7 forbidden-pattern audit is green.
- [ ] IPv4/IPv6/IP-URL/CIDR/SNI/Host/non-standard-port fixtures are green.
- [ ] Undeclared SNI, Host and port values are denied before connector invocation.

## Tester triage and reporting

- [ ] Tester triage supports HTTP, HTTPS, IPv4 and IPv6.
- [ ] Actionable / Needs-review / Not-actionable UI tabs render as views only.
- [ ] Every finding remains stored and every scan finding appears in the v3 report.
- [ ] Unclassified findings default to Needs-review and remain reportable.
- [ ] No `handling_policy`, `handling_rule`, `policy: unspecified`, or policy citation is required for report inclusion.
- [ ] Verification state is shown when present; absence displays `not-recorded` and never suppresses a finding.
- [ ] “Why this rank” resolves to tester priority, severity, disposition and duplicate-risk inputs.

## SSE and replay

- [ ] `finding`, `progress`, `log`, `evidence`, `chain`, `ranked`, `verification`, `disposition`, and `target` all use `windeep.sse.v1`.
- [ ] Event sequence is monotonic and encrypted at rest.
- [ ] Reconnect test with `Last-Event-ID` is gap-free.
- [ ] Export/broadcast payloads pass the existing secret-redaction sanitizer.

## Automated release gates

Run from a clean checkout:

```bash
python scripts/audit/release_audit.py --phase A
python scripts/audit/release_audit.py --phase B
python scripts/audit/release_audit.py --phase V3
python -m pytest -q --cov=app --cov=launcher --cov-report=term-missing --cov-report=xml:reports/coverage-v3.xml --cov-fail-under=85
python scripts/audit/ui_v2_smoke.py
```

- [ ] Overall coverage is at least 85%.
- [ ] Every new v3 module is at least 90% covered.
- [ ] Phase A/B audits pass.
- [ ] Phase V3 audit passes.
- [ ] Full pytest passes.
- [ ] Browser/UI smoke passes.

## Manual verification note for the release PR

Record exact commands and resulting scan id for a fixture scan. Then reproduce all of the following from the encrypted store alone:

1. Open the scan's persistent SSE endpoint and save the last sequence id.
2. Reconnect with `Last-Event-ID: <seq>` and confirm replay resumes at `<seq + 1>` without a gap.
3. Open **Findings & Proof** and inspect **Actionable**, **Needs-review**, and **Not-actionable** tabs.
4. Classify one HTTP/HTTPS or IPv4/IPv6 finding and inspect **Why this rank**.
5. Inspect at least one verification badge; also confirm a `not-recorded` finding remains visible.
6. Generate the v3 all-findings report and confirm the finding count equals the scan's normalized finding set.
7. Export a redacted HAR and the v3 report; confirm no unredacted secret survives.
8. For an IP-URL fixture, confirm replay stays pinned to the literal server IP.
9. Verify the artifact hashes, redaction map hash, flow/replay handles where present, and append-only custody/audit log.
10. Confirm the same report inputs and durable event history can be reconstructed from the encrypted store without network discovery.

## Release cut

- [ ] PR stack is green and reviewed.
- [ ] No workstream PR is merged out of order.
- [ ] Create/tag `v3.0.0` only after every checkbox above is satisfied.
- [ ] Any post-freeze contract fix is released as v3.0.x, not by silently changing v3.0.0 schemas.
