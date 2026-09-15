# V3 handling alignment

Windeep v3.0.0 uses **tester-first triage**. It does not require an imported reviewer policy before findings can be classified, ranked, displayed, exported, or reported.

## Scope of the v3.0.0 handling model

The supported triage asset classes are `http`, `https`, `ipv4`, and `ipv6`. A tester may assign one handling disposition to a finding:

- `actionable` — the tester believes the finding is ready to surface prominently.
- `needs-review` — the finding remains visible but requires more tester or reviewer attention.
- `not-actionable` — the tester does not consider it actionable in the current review pass.
- `informational` — the finding is context rather than a direct action item.

Every manual classification stores the tester priority, duplicate-risk estimate, and a non-empty rationale. There is no `handling_policy` or `handling_rule` dependency in v3.0.0.

## Classification is never suppression

A disposition changes ordering and UI grouping only. It never deletes the underlying finding and never removes it from the final v3 report. Unclassified findings remain visible and default to `needs-review` with the rationale `Tester has not classified this finding yet.`

The final report is an **all-findings report**. P3 evidence-backed detail is embedded when available. If an evidence bundle cannot be rendered, the normalized finding still appears with the evidence-detail availability reason. A missing policy, missing tester classification, or missing verification record is therefore not a report-suppression condition.

## Ranking before external alignment

The v3 score is deterministic and tester-driven:

`base = 0.60 × tester_priority + 0.40 × severity_weight`

`score = base × disposition_factor × duplicate_factor`

Severity weights are Critical 100, High 85, Medium 60, Low 35, Info 10. Disposition factors are actionable 1.00, needs-review 0.85, not-actionable 0.35, informational 0.20. Duplicate factors are low 1.00, medium 0.85, high 0.70.

This deliberately permits an actionable High finding to rank above a Critical finding the tester marked not actionable. CVSS remains visible in the report but does not override the tester's handling decision.

## Verification and evidence

R5 verification records remain part of the release evidence model and may be displayed beside a finding. They are not used to decide whether a finding is included in the v3 report. If verification is present, the report can show `verified`, `partially_verified`, or `needs-review` claim state. If it is absent, the report shows `not-recorded` and still includes the finding.

Raw evidence remains encrypted. Reports and UI surfaces consume redacted views and stable artifact/flow references when available.

## Future reviewer alignment

A later v3.x release may add optional reviewer/program alignment or policy imports. Such alignment must be additive: it may annotate or reorder findings but cannot retroactively delete, hide from export, or rewrite historical tester classifications. Any future exclusion concept must remain a view/filter rather than a purge.

## Tests

`tests/test_v3_manual_triage.py` asserts supported asset classes, fail-closed triage input validation, no-finding deletion, actionable-High ordering over tester-marked non-actionable Critical, deterministic reporting, all-findings inclusion, and absence of policy-gated report language.
