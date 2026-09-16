# Windeep v3 glossary

This glossary is the canonical vocabulary for the v3 UI, SSE payloads, evidence bundles, triage records, and reports.

## `exploitability`

Describes whether Windeep can support a conclusion using its non-exploit validation boundary. `observed` means the behavior was directly observed without exploitation. `needs-human-review` means stronger confirmation would require a human decision or a step outside automated non-exploit validation. Exploitability is not the same as severity, confidence, handling disposition, or verification state.

## `handling_disposition`

The tester's operational handling choice for a finding. v3.0.0 supports `actionable`, `needs-review`, `not-actionable`, and `informational`. A handling disposition affects rank and UI grouping only. It never deletes a finding and never removes it from the all-findings report.

## `triage_readiness`

A derived presentation concept describing whether a finding is ready for immediate tester action. v3.0.0 does not persist a separate triage-readiness field because tester handling disposition plus evidence/verification state already convey that information. UI and report code must not invent a second conflicting readiness state.

## `confidence`

The producer's confidence in the normalized finding, expressed as a value from 0 to 1 where available. Confidence does not override evidence, verification, severity, or tester disposition. A high-confidence informational finding may still rank below a lower-confidence actionable finding after tester triage.

## `verification_state`

The evidence state of a claim. Persisted R5 states are `verified`, `partially_verified`, and `needs-review`. The v3 UI/report may additionally display `not-recorded` when no verification record exists. `not-recorded` is a neutral display state and never suppresses the finding.

## Ranking vocabulary

`tester_priority` is the tester's 0–100 importance input. `duplicate_risk` is advisory (`low`, `medium`, or `high`). `score` is the deterministic v3 rank score calculated from tester priority, severity, handling disposition, and duplicate risk. “Why this rank” surfaces those inputs; it does not replace the underlying finding or evidence.
