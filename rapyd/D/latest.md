# Rapyd D — 2026-11-09 13:00 UTC

NEW: Three distinct unverified hypotheses ranked: checkout merchant-return binding (4), verification return-state replay (3), cross-origin message origin validation (2). Scores are relative triage only, not severity.

Selected: checkout.rapyd.net merchant-context substitution on hosted checkout return. Public scope mirror lists hostname, but current official Bugcrowd participation/brief unverified and no deployed code/version evidence; G0/G1 false. Attacker would need control over browser return parameters. Strongest defense: server-side session and merchant binding with one-time state, never trusting browser-supplied merchant identity.

Offline JS strict equality fixture: verify('merchant-B','merchant-A') => false (cross-merchant negative authorization); verify('merchant-A','merchant-A') => true (valid control). Both observed. No Rapyd endpoint called; fixture only, G2_TARGET=false. No independent Rapyd impact; G3/G4 false.

Dedupe: A frontend assets, B auth tenant/signing, C backend parsing, E webhook finances; no matching published lane fingerprint at read time. Public metadata only. No private package, Library verification, chat delivery or submission. NEXT: obtain current authenticated official Bugcrowd brief and verify researcher participation before considering any target experiment.
