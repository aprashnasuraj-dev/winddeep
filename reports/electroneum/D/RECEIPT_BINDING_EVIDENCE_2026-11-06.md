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

## 2026-11-06 15:46 NPT — additional certified dispatcher ordering proof and execution blocker

**Decision: SUSPECTED broader typed-receipt normalization/restart route; the independent peer-metadata injection sub-route is SOURCE-DISPROVEN within ordinary eth/66 dispatch.** No confirmed security finding; P1–P3/CVSS not established.

Fresh certified-source reads at immutable commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`:
- `eth/protocols/eth/dispatcher.go:153-182` `(*Peer).dispatchResponse` first matches a pending request, calls the response decode closure, sets `res.Res=data`, then calls the metadata closure and sets `res.Meta=metadata()`. It forwards the paired response only afterward at lines 189-200. This is stronger than merely observing a shared captured slice: metadata generation is sequenced after successful decoding and before response delivery. A peer cannot directly populate `res.Meta` through this path.
- `eth/protocols/eth/handlers.go:498-530` `newRawTypedList` uses `rlp.SplitList` and `rlp.Split` with minimum-length and typed-envelope structural checks. It rejects undersized legacy entries and typed strings without a type byte followed by list encoding. This is structural validation, **not** proof that every semantically invalid receipt is rejected after trie-root matching.
- `eth/downloader/fetchers_concurrent_receipts.go:90-94` forwards the response payload and locally generated metadata as one object. The queue checks the root before decoding.

**Completed scoped falsification:** An external eth/66 peer cannot independently inject an honest claimed receipt hash alongside unrelated malicious raw receipts through the normal handler/dispatcher sequence. A synthetic direct queue call with mismatched raw/hash metadata does not cross the network trust boundary. This falsifies *only that route*, not typed receipt parser equivalence or persisted canonical read/restart behavior.

**Actual execution status:** Tried `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` in local shell; failed `Could not resolve host: github.com` (exit 128). No certified checkout could be bootstrapped locally. GitHub connector successfully read the certified source but exposes no direct arbitrary Go execution or workflow dispatch action; this invocation did **not** run a new Go test, perform an independent runtime oracle, or reopen a database. Historical CI run `42172102719` still proves only the earlier five queue tests. Do not label this an executed typed-receipt or persistence experiment.

**Next narrow executable experiment:** In the already authorized class-owned certified Actions workflow (only if no class CI active), add a <=10-minute Go test under `eth/protocols/eth` using honest receipt RLP, legacy malformed item, typed malformed envelope, and typed reorder. Compute the independent expected trie root from receipt objects, compare to `handleReceipts66` metadata after dispatch, then independently test reopened on-disk raw/derived receipts in an isolated `core/rawdb` fixture. Preserve authenticated header and do not create a forged local-header acceptance claim. Capture actual test names, exit codes and logs. No new long fuzz campaign.

**Counterexample:** Structural rejection at `newRawTypedList`, metadata derived from exactly the decoded bytes after request match, and authenticated-header root comparison together prevent the simple forged-hash route. No evidence presently defeats those guards. The broader HYP-D-003 remains open; no external vulnerability report is authorized.
