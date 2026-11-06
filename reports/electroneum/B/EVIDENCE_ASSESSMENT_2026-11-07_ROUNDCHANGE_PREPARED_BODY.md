# Class B evidence assessment — 2026-11-07 NPT

**Lead:** B-RC-PREPARED-BODY-SUBSTITUTION. **Decision:** DISPROVEN within the inspected decoder path (source-contract scope only). **Reportability:** NO CONFIRMED FINDING. **Hypothetical band before falsification:** P1 if one Byzantine validator could substitute an uncommitted prepared block and induce invalid finality; no assigned CVSS.

## Question and reachability
Could an authenticated Byzantine validator alter the unsigned `ROUND-CHANGE.PreparedBlock` body while retaining the signed prepared digest, causing a proposer to re-propose a different transaction body? Authenticated validator network input is the candidate ingress; no unauthenticated route established. Score before investigation: hypothetical P1 × authenticated-validator reachability / low inspection effort. Prior backlog-priority lead remains DEFERRED, not reopened.

## Immutable source and new checks
Read immutable certified object at `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` (documented subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`), exact files:
- `vendor/electroneum-sc/consensus/istanbul/core/handler.go`: `handleEncodedMsg`, `preVerifySignature`, `checkRawBlock`.
- `vendor/electroneum-sc/consensus/istanbul/types/roundchange.go`: `RoundChange.DecodeRLP`.
- `vendor/electroneum-sc/consensus/istanbul/core/roundchange.go`: `handleRoundChange`.

New connected-source contract execution: **7/7 JavaScript assertions true**, covering early outer-signature check, empty prepared-block special case, header/digest binding, transaction-trie root binding, uncle-hash binding and later round-change justification. These are source assertions, **not certified Go execution**. Local command `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` exited 128, DNS resolution failed. `go version` returned go1.23.2. No bootstrap or target-runtime Go tests ran.

## Observed versus expected
**Potential attack:** A validator signs the prepared header digest, then swaps transactions without changing the header. **Source-observed defense:** `RoundChange.DecodeRLP` checks prepared-block header hash against the signed prepared digest, and separately recomputes transaction trie root and uncle hash against the header. Thus changing transactions or uncles while retaining the signed header is rejected in the inspected decode path. `preVerifySignature` authenticates the outer sender before full decoding. An empty prepared block is a permitted no-prepared-state form, not by itself a missing signature check.

**Honest control (source contract):** valid header, matching body commitments, matching signed digest can pass these specific checks; other checks still apply. **Malicious control (source contract):** altered body with stale header commitment fails decoder comparison. **Boundary controls:** empty prepared block is intentionally accepted as empty; mismatched header digest fails. These are code-path deductions, not observed signed runtime fixtures.

**Strongest counterexample to a vulnerability:** both transaction-root and uncle-root integrity checks already exist in the shipped decoder. The body-swap theory fails at this boundary absent a separately demonstrated hash collision, alternate decoder or bypass. No invalid finalization or outage observed. E1 only; E2/E3/E4 absent. No external report.

## Next discriminating action
Rotate to a genuinely distinct high-value authenticated QBFT stateful lead; prioritize certified signed-message runtime execution through actual handler paths. Reopen this candidate only if a production route bypassing `RoundChange.DecodeRLP` is demonstrated. No new fuzz campaign or CI dispatch.
