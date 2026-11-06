# HYP-D-003 — Certified receipt-payload/metadata binding assessment (2026-11-06 NPT)

**Disposition: SUSPECTED broader receipt-ingestion integrity; narrow independent-peer-hash injection route SOURCE-FALSIFIED (E1), not E3 DISPROVEN; NO E4 confirmed vulnerability.** Provisional Bugcrowd P3 is hypothetical, *not* a validated severity or CVSS score. Do not publish as an external vulnerability finding.

## Certified identity and scope

- Certified immutable Git source commit: `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`.
- Certified tree: `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned upstream: `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive SHA-256 provenance: `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.
- These values come from the existing certification contract. **This invocation did not execute the bootstrap, verify the full runtime identities, or execute Go tests.** It directly fetched source files from the immutable Git commit and confirmed the identical file blob on the live audit branch. Source equality is E1, not a fresh executed runtime E2.
- Certified `eth/protocols/eth/handlers.go` blob `31551ed59ac4fceb12c81fe1c74951b6773fa7f5` matches the same branch path. Certified `eth/downloader/fetchers_concurrent_receipts.go` blob `1d12be1f61191a23e00b5c3c8f771f78d38c41d5`; `eth/downloader/queue.go` blob `5eb0e1f526afeeb84b382430d450a23c62d07740`. Source read via connected GitHub, not mutable vendor checkout.

## Production-style eth/66 ingress and strongest counterexample (E1 source-read)

1. `eth/protocols/eth/handlers.go:572-590`, `handleReceipts66`: decodes the request-ID envelope and a bounded RLP receipt list; the `receipts` captured by the decode closure are the input to the later metadata closure.
2. `eth/protocols/eth/handlers.go:592-606`: metadata loops over that **same decoded `receipts` array**, passes each to `newRawTypedList`, computes `types.DeriveSha(list, trie.NewStackTrie(nil))`; structurally unsuitable input is assigned the zero hash; `peer.dispatchResponse` receives both closures. There is no independently peer-provided trusted receipt-root field in this eth/66 metadata producer.
3. `eth/downloader/fetchers_concurrent_receipts.go:90-94`, `(*receiptQueue).deliver`: forwards `packet.Res` (raw receipt payload) and `packet.Meta` (locally derived hashes) to `q.queue.DeliverReceipts` in a single response object.
4. `eth/downloader/queue.go:805-827`, `(*queue).DeliverReceipts`: compares each supplied local metadata hash against the requested header's `ReceiptHash` before decoding receipt payload; `queue.go:835-904` `deliver` associates responses by request order, accepts valid prefixes and returns failures to task queue.

**Strongest counterexample to the proposed exploit:** a peer sends mutated receipt RLP and an unmodified claimed root, but the shipped eth/66 handler does not use that claimed root: it independently hashes the mutated RLP and passes the computed root to the queue. A direct test invoking `DeliverReceipts(rawMalicious, hashHonest)` violates the upstream-producer contract and is NOT evidence of attacker reachability.

## Historical certified runtime behavior (E2, NOT new execution)

Original trigger `f1673f314c9210e0d6df80f0fe555e29b06cf9bd`; CI run `42172102719`, job `127742078235`, conclusion success. Previously inspected decisive command: `go test -count=1 -timeout=12m -run TestWorkerDReceiptPartialDelivery -v ./eth/downloader` (exit 0 in the prior certified CI). Five subtests actually executed: honest_all_valid; valid_prefix_invalid_second_then_retry; same_length_swapped_receipt_lists_rejected; honest_prefix_then_swapped_suffix_rejected; invalid_first_keeps_all_pending. The two equal-length swapped-root controls were rejected. This establishes queue-level behavior only; no synthetic signed competing chain, peer-path end-to-end execution, independent trie-root implementation, deliberately weakened check, canonical-write/restart observation, or security loss was demonstrated.

## Expected vs observed and competing explanations

- H1 — remote peer supplies independent correct hash with malicious bytes: **SOURCE-FALSIFIED for ordinary eth/66 path** by local metadata derivation, E1. This is not a universal disproof of other protocols, typed-receipt normalization bugs or caller misbinding.
- H2 — same-length distinct receipt-root swaps survive ordered queue validation: existing E2 queue test shows rejection for tested fixtures. E3 scoped disproof still requires an independent oracle plus mutation-sensitivity control.
- H3 — malformed/noncanonical typed receipt encodings hash differently before/after decoding, or later derived metadata/indexing becomes inconsistent: **UNTESTED / ACTIVE**. Analyze `newRawTypedList`, `eth.DecodeReceipts`, and persistent `ReadRawReceipts` vs `ReadReceipts` under canonical authenticated headers; run clean and adversarial controls and independent root oracle.

No evidence of altered finalized history, external-controlled persistence, or funds/correctness harm. CVSS scoring and Bugcrowd band determination are therefore **not justified**. No external vulnerability report is warranted.

## Exact next discriminator

In a scratch copy bootstrapped from the immutable certified object, run a short deterministic eth/66 receipt-packet test through `handleReceipts66` and the real response dispatch, with honest receipts, equal-length swapped receipts, malformed typed envelope and reordered typed receipts. Independently compute receipt trie commitments and compare actual `packet.Meta` with payload before the queue. Include a deliberately weakened scratch-only root check and require the test to fail; then verify no canonical write/head change or persisted raw/derived receipt disagreement after reopened state. Log `go version`, `-count=1 -v`, named tests, actual exits and source bootstrap identities. This is a pending experiment, **not executed in this assessment**.

## Ownership and report boundary

Only Class D files are in scope. No upstream modifications, live-node traffic, workflow dispatch/cancellation, or external disclosure. Keep HYP-D-003 open as a broader investigation, while recording the narrow eth/66 forged-metadata sub-route as source-falsified.
