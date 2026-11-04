# Worker R: deeper attack surfaces after E-RPC-004 closure

Certified Electroneum source: Windeep commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0 and tree de7f3c75a2db7e87a89918f1257820703d5b731e. These are branch-isolated, bounded, source-runtime experiments with no real keys, endpoints, validator network or on-chain writes.

| Track | Deeper boundary | Positive control | Adversarial oracle |
|---|---|---|---|
| D1 RPC batch | HTTP -> JSON codec -> service registry -> batch result | rpc_modules requests with unique IDs | Intermixed invalid method IDs never contaminate valid results; 5MiB unknown-length body cannot yield accepted valid RPC |
| D2 nested ABI | dynamic arrays of dynamic byte strings (two recursive levels) | correct bytes[] and bytes[][] encodings | semantically targeted offsets/length words are either safely rejected or decoded within input-sized resource bounds |
| D3 signed transaction envelope | signature -> legacy/EIP2930/EIP1559 -> binary/RLP -> signer identity | 3 synthetic signed transaction types and cross-chain replay denial | mutations either error or canonical accepted binary roundtrip with stable hash |
| D4 coupled downloader queues | trusted block bodies + receipt RLP + concurrent revoke/expire/reset | valid body and receipt deliveries both finish | poisoned roots rejected, stale responses denied, both task pools recover after mixed races; race detector baseline |

Each run is a separate branch with selector.txt and exact SHA checkout; it certifies the immutable source, mounts tests only in scratch, runs controlled baseline with an actual package coverage report, then Go's coverage-guided fuzzing for 35 seconds with two workers, 768MiB memory budget and 14-day artifacts for failures and reproducers.

**Evidence standard:** package coverage is not whole-node reachability. No test failure is a vulnerability finding until compile/fixture assumptions, positive controls, attacker influence, and production impact are separately verified. The earlier E-RPC-004 finding remains one source-level discrepancy, regardless of repeated fuzz reproductions. Do not modify the certified source or other workers A-E.

**Scope exclusion:** transaction-pool state-reset fuzz, downloader cancellation and original simple ABI array fuzz already have separate stateful tracks. D1-D4 deepen those boundaries with mixed actual queue families and nested formats.
