# V5 engine and submission alignment audit

This audit is a static contract review of the 137 registered integrations at
the parent revision. It is not a claim that each external tool was installed,
executed, or independently verified on Windows, Linux, WSL, containers, or
remote workers.

| Check | Result | Change |
| --- | --- | --- |
| Registry | 137 integrations in eight categories; 130 line parsers, seven JSONL parsers | Contract regression checks all wrappers and template fields. |
| Diagnostic commands | 23 effective commands have no target input and no builtin target-aware fallback. Five were enabled by default. | Mark as diagnostic, exclude from broad scans, and retain their raw output without creating findings when explicitly selected. |
| Authorized target | Per-tool options could overwrite the target after scope validation. | Reject a target key in options and reserve that field in schemas. |
| Structured results | JSONL normalization discarded recorded steps, impact, remediation, request, response, and CVSS vector. | Preserve these fields as tool-reported content; do not accept a tool's self-asserted verification. |
| Confidence | A recorded zero was replaced by 0.5 during persistence; malformed ranking inputs could raise or become non-finite. | Preserve zero and handle malformed/non-finite values deterministically. |
| Submission export | The evidence-backed finding exporter was not available in the desktop workflow. | Add scan-bound drafts with redacted evidence, Markdown/HTML/HAR, a structured payload, and a SHA-256 manifest. |

Diagnostic classification is based on the current effective command templates.
It does not establish that all remaining commands use valid flags, emit useful
results, or cover the intended vulnerability classes. Generic line output is an
observation, not independently confirmed proof. A real adapter-quality audit
still needs isolated fixtures and runtime testing for each supported backend.

## Preparing a submission draft

Open **Findings & Proof**, choose a finding, enter an authorized source scan ID,
select a format, and choose **Review draft**. The ZIP contains `report.md`,
`report.html`, `evidence.har`, `submission.json`, and `manifest.json`, plus any
approved redacted screenshots. The platform payload is a copy/paste template;
it does not submit anything or assert compatibility with a live platform API.

The export requires a terminal scan, current scan consent, an associated
finding, and a closed, integrity-checked evidence bundle for that same scan.
Unscored findings display their stored severity without inventing a CVSS vector.
The draft identifies missing material and always requires human review of the
steps, expected versus observed behavior, impact, program rules, duplicates,
and all attachments. Automatic redaction cannot guarantee removal of all
secrets or personal data.

## Release limits

The parent evidence/runtime PR must be reviewed and merged before this branch.
This work does not certify the installer, fix every open report defect, benchmark
detector recall or false positives, or establish that v5 is ready to ship.
