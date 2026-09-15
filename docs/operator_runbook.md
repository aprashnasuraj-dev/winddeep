# Windeep v3 operator runbook

## 1. Start from explicit authorization

Create/select the authorized root target, record scope/out-of-scope rules, and issue signed local consent before a scan. V3 target declarations may represent domain, subdomain, IPv4, IPv6, CIDR, IP range, URL, IP-URL, service, contract, or source repository. Ports, SNI values and Host values are explicit declaration data; reverse DNS never expands scope.

For CIDR/IP-range targets, declare `max_hosts`. A single declaration is limited to 4096 auditable candidate hosts. Split larger ranges into separately consented declarations.

## 2. Run the v3 scan

The release pipeline order is scope+consent → recon → engines → dedup → chain → rank → hypothesis → tester handling → bundle close → verification → report → export/submission. Every target/tool action remains behind the same preflight controls.

Use the scan center normally. The persistent scan stream is `/api/v2/scans/<scan_id>/events`; the frozen schema remains `windeep.sse.v1`. Reconnect with the last received sequence as the `Last-Event-ID` header to replay without gaps.

## 3. Tester triage

Open **Findings & Proof**. V3 presents three views:

- **Actionable** — findings the tester has marked actionable.
- **Needs-review** — findings requiring more judgment; unclassified findings appear here by default.
- **Not-actionable** — tester-marked not-actionable and informational findings.

For HTTP, HTTPS, IPv4 and IPv6 findings, set disposition, tester priority (0–100), duplicate risk, and rationale. The **Why this rank** disclosure shows the ranking inputs. Classification changes prominence only; it never deletes a finding.

## 4. Verification surface

A finding can show `verified`, `partially_verified`, `needs-review`, or `not-recorded`. Verification is evidence annotation, not an inclusion gate. `not-recorded` means no R5 record exists; the finding remains visible and reportable.

## 5. Generate the v3 report

The Reports view generates the v3 all-findings report from the latest authorized scan for the selected target. The report includes every normalized finding whether classified or unclassified and whether verification is present or absent.

Where a closed P3 evidence bundle is available, the v3 report embeds its redacted evidence, reproduction, impact, remediation and provenance detail. If detailed evidence cannot be rendered, the normalized finding still appears with an explicit evidence-detail availability message. Raw evidence remains encrypted in the store.

## 6. Inspect literal-IP evidence

For IP-addressed HTTPS, inspect separate certificate-verification observations. Confirm peer/server IP, SNI sent, Host sent, TLS version/cipher, certificate fingerprint/chain availability and verification outcome. Replay records pin the literal IP; DNS or PTR output does not retarget them.

## 7. Export and custody checks

Before sharing an export:

1. confirm the report contains the expected full finding set;
2. inspect redaction and ensure secrets are absent;
3. verify evidence/artifact hashes and replay handles where present;
4. inspect the append-only audit/custody log;
5. confirm the encrypted store alone can reproduce the report inputs and durable SSE history.

## 8. Release verification commands

From a clean checkout:

```bash
python scripts/audit/release_audit.py --phase V3
python -m pytest -q --cov=app --cov=launcher --cov-report=term-missing --cov-fail-under=85
```

New v3 modules must remain at least 90% covered. Existing Phase A/B audits and UI smoke must also remain green.
