# TransferWise / Wise GitHub audit lane

## Executive boundary

This branch treats **public repositories under `github.com/transferwise/*` as the declared GitHub/Recon scope**, with one explicit exception: **`transferwise/pipelinewise` is out of scope**.

The lane is deliberately source-first and read-only. It inventories repositories, shallow-clones only scope-approved repositories, generates static review candidates, and preserves evidence artifacts. It does **not** turn scanner output into findings, perform credential logins, exploit network targets, or submit reports automatically.

## Scope gates

| Decision | Rule |
|---|---|
| In scope | Exact GitHub repository owner is `transferwise` |
| Out of scope | `transferwise/pipelinewise` |
| Out of scope | Any repository outside the `transferwise` organization |
| Third-party/upstream code | Candidate may be reviewed, but rewardability requires a Wise-specific vulnerable change, integration, configuration, or impact |
| Sample/placeholder secrets | Suppressed when clearly examples/tests/fixtures/docs/CI placeholders |
| Public leaked credentials | Not promoted by automation; program-compliant manual evidence is required |
| Scanner/static output | Candidate only; never a finding by itself |

## Audit lifecycle

1. **Inventory:** enumerate all public repositories in the organization through the GitHub API.
2. **Fail-closed scope check:** reject any owner other than `transferwise`; reject the exact `pipelinewise` repository.
3. **Prioritize:** favor active, non-fork, security-sensitive or integration-heavy repositories. Inventory still records all authorized repositories.
4. **Read-only checkout:** shallow clone the selected repository at an exact commit.
5. **Candidate generation:** inspect source and workflows for high-signal patterns. Obvious sample/test placeholders are suppressed.
6. **Evidence gate:** every candidate remains `reportable=false` until a specific PoC, reproduction, demonstrated impact, Wise-specific review where needed, and duplicate review are supplied.
7. **Dedupe:** the supplied scope states five issues are already known/reported. Their fingerprints are not available here, so the workflow marks every candidate as requiring manual duplicate review rather than inventing dedupe certainty.
8. **Submission:** remains a human decision outside this workflow.

## First detectors

The initial lane focuses on source-level patterns where repository ownership and exact-line evidence can be preserved:

- privileged GitHub Actions triggered through `pull_request_target` while checking out PR-head code;
- attacker-controlled event expressions interpolated into shell `run` blocks;
- overly broad `write-all` workflow permissions **only as a lead**, requiring an attacker-controlled path to become meaningful;
- non-placeholder hardcoded secret/private-key candidates;
- `shell=True` and unsafe YAML-load candidates that require explicit input-flow proof.

These are intentionally **candidate generators**. A component-level smell is not a system-level vulnerability.

## Current automatic run

A push to the `transferwise` branch runs policy tests, inventories the organization, then audits the top 30 prioritized repositories with at most four parallel jobs. Manual dispatch can set `limit=0` to cover the entire in-scope inventory, but large third-party mirrors can consume substantial CI time and should generally be reviewed only for Wise-specific deltas.

## Known gap

The program states that five issues have already been reported, but no titles/fingerprints were supplied. The configuration stores the count and an empty fingerprint ledger. Add non-sensitive fingerprints/summaries when available so duplicate filtering can become specific rather than merely mandatory.
