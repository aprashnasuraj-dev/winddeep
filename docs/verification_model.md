# V3 verification model

Verification in Windeep v3 is an **evidence annotation**, not a report-inclusion policy.

## States

A stored claim verification may be:

- `verified` — the claim resolves to captured evidence such as a flow, artifact slice, or deterministic replay reference.
- `partially_verified` — part of the claim is directly evidenced while another part remains inferred or requires judgment.
- `needs-review` — a human decision or observation is still required and the verification record carries the review plan.

If no verification record exists, the v3 report uses the neutral display state `not-recorded`. The finding is still rendered.

## Relationship to the all-findings report

The final v3 report contains every normalized finding for the scan. A verification record can strengthen the evidence block and provide claim-level state, but it does not determine whether the finding appears. The same non-suppression rule applies to tester triage: classification changes order/grouping only.

When P3 can render a closed evidence bundle, the v3 report embeds that evidence-backed detail. If the evidence bundle is missing or incomplete, the report keeps the normalized finding and records why the detailed evidence subsection could not be rendered. This makes absence visible instead of silently deleting the input.

## Hash-addressed records

R5 verification records remain hash-addressed P1 artifacts and may be resolved from the encrypted store. They are deterministic for the same finding, bundle and evidence references. Report output cites the verification artifact hash when one exists.

## Safety boundary

Verification does not authorize active exploitation. Observation-only reproduction and deterministic replay remain the automated validation boundary. Any stronger confirmation that would require exploitation remains a human review decision.

## UI

The v3 findings view shows a verification badge for each item: `verified`, `partially_verified`, `needs-review`, or `not-recorded`. The badge is informational and never hides the finding.

## Regression tests

`tests/test_v3_release_wiring.py` covers hash-addressed verification records and human-review plans. `tests/test_v3_manual_triage.py` covers all-findings reporting with both present and absent verification records.
