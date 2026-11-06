# C-006 — 2026-11-06 18:36 NPT — independent source-path boundary verification

**Decision:** DISPROVEN for the narrow claim that ordinary signed canonical transactions inherit the RPC simulation `IsFake` nonce bypass. **Overall:** NO CONFIRMED REPORTABLE FINDING. Evidence E1 only; no fresh certified-runtime execution.

## New execution this run
Immutable certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` was fetched through the connected GitHub source interface. A deterministic five-file string-location cross-check executed over fetched source text (not a Go test). Results:
```
core/types/transaction.go chars=22349 AsMessage=line 637 isFake:=line 632
core/state_processor.go chars=8665 AsMessage(=line 78 ApplyTransaction(=line 172
core/state_transition.go chars=15250 preCheck=line 218 IsFake()=line 81 ErrNonceTooHigh=line 224 ErrNonceTooLow=line 227
internal/ethapi/api.go chars=75989 DoCall=line 902
internal/ethapi/transaction_args.go chars=10980 ToMessage=line 181 true, priorityPubkey=line 251
```
This cross-check proves source presence/locations, **not execution semantics**. Existing source review shows `AsMessage` constructs nonfake signed messages; RPC `ToMessage` constructs fake simulation messages; block processor calls `AsMessage`; nonce checks are guarded by `IsFake`. Positive control: canonical signed-message path contains `AsMessage`. Negative control: RPC simulated message explicitly uses fake flag; it is not a signed transaction. Two boundary variations are nonce below and above state nonce: both have distinct error branches in `preCheck`; expected behavior is rejection, **not runtime observed this run**.

## Environment and provenance
Local command: `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` => exit 128, DNS resolution failure (`Could not resolve host: github.com`). No certified bootstrap, Go test, independent state oracle, or three-run breach execution; no new CI dispatched. Expected certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` were not independently rehashed. Source URL: https://github.com/aprashnasuraj-dev/winddeep/tree/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc .

## Strongest counterexample and remaining proof
A custom unreviewed caller could construct a fake message and write its result to persistent state; no such production caller or external ingress was demonstrated. Source-only inspection cannot exclude all such paths. An attacker cannot simply set `IsFake` on a signed transaction through the reviewed canonical ingress. No unauthorized funds, signing, or P2+ impact shown. Next discriminating action: run an existing class-owned certified Go fixture on the GitHub Actions runner, if no Class C job is active, to compare nonce-1/nonce/nonce+1 and simulation state persistence against an independent oracle. Do not promote to external report absent E4.
