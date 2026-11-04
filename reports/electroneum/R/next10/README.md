# Electroneum Worker R: ten independent adversarial CI experiments

**Scope:** Certified Electroneum source tree `de7f3c75a2db7e87a89918f1257820703d5b731e` at immutable commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; never modify this target. All tests are synthetic local cases, no real key, live chain, or external endpoint.

| Run | Attack aspect | Core oracle |
|---|---|---|
| 01 | JSON-RPC HTTP ingress | Valid request succeeds; disallowed methods, content types and oversized declared bodies fail closed |
| 02 | JSON-RPC batch isolation | 3 distinct IDs; invalid method cannot contaminate successful replies |
| 03 | Hex quantity canonicality | Reject leading zeros, missing prefix, overflow |
| 04 | RLP canonical integer and size | Reject overlong length, trailing objects, invalid integer |
| 05 | ABI dynamic pointer integrity | 64 out-of-bound offsets plus 256-bit overflow and truncation |
| 06 | ABI allocation safety | Reject overstated dynamic-array counts, including huge lengths |
| 07 | secp256k1 scalar limits | Accept 1 and N−1; reject 0, N, N+1 and invalid widths |
| 08 | Signature malleability | Positive recovery; reject high-S and invalid recovery IDs |
| 09 | EIP-155 replay domains | Positive recovery for 16 chain domains, rejection on 16 foreign domains |
| 10 | EIP-2718 typed transaction envelope | Positive binary roundtrip; reject unknown envelope and truncations |

Each experiment is a **separate GitHub Actions run on an isolated branch**. Every workflow pins the triggering SHA, validates the certified Electroneum source, runs one selected test (with zero-test guard), and reports results in CI logs. Passing tests confirm only these particular checked properties, not overall safety.

A failing Go test is an *untriaged signal* until the cause is distinguished among setup/fixture defects, genuine source behavior, and exploitable production behavior. The original Worker R workflow and the main audit branch are left unchanged.