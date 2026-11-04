# Worker R P2l — Nonvalidator noncanonical QBFT data, NodeData request-ID enforcement, peer-churn storage oracle

**Verified date:** 2026-11-04 UTC  
**Branch:** `audit/r-production-depth-20261104-21-noncanonical-nodedata-churn`  
**Passing expanded test:** [GitHub Actions #41813355744](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41813355744)  
**Evidence artifact:** [r-production-depth-41813355744-1](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41813355744/artifacts/13313586332) (expires 2026-11-18)  
**Immutable certified Electroneum source commit:** `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`  
**Certified source tree:** `de7f3c75a2db7e87a89918f1257820703d5b731e`  
**Test source:** `reports/electroneum/R/production_depth/qbft_eth66_nodedata_noncanonical_churn_test.go`  
**Workflow:** `.github/workflows/electroneum-r-production-depth.yml`, selector `21-noncanonical-nodedata-churn`

## Executive result

**NO NEW REMOTELY EXPLOITABLE PERSISTENT-DISK VULNERABILITY ESTABLISHED.**

P2l uses live TCP/RLPx/ETH66 peers with no access to validator private keys. A trusted fixture builds a canonical 3-of-4-QBFT block and a valid successor, then **removes one committed seal from the successor**, leaving **2-of-4 seals**. A real network peer advertises and propagates that altered successor and separately provides the invalid header and body in replies to genuine ETH66 requests. The shipped QBFT verifier rejects the received header (`invalid committed seals`). The body is delivered to the diagnostic request sink, but the test **does not submit the body to the production importer**.

The same campaign tests one properly matched 32 KiB NodeData packet, a two-node response to a single-node request (requested-items overlimit), a response of the wrong packet type, and three unsolicited ~64 KiB NodeData replies from new network identities. It measures per-session filesystem allocation and process-level CPU plus wall time.

**All 10 bounded peer sessions left 0 additional physical LevelDB bytes allocated.** After explicit full compaction and shutdown/restart, the ETH66 and independent direct-import databases occupied **28,672 bytes each**. No unexpected canonical head or transaction receipt modification was observed; the invalid block remained unavailable by hash.

## Threat and authority boundary

- The network actor controls its own **unprivileged p2p identity**, connected sockets, ETH66 response IDs and payloads, and already-available but deliberately under-signed noncanonical chain data.
- It **does not possess any QBFT validator key**. The fixture's four signer keys are used exclusively to build the positive-control valid chain and a valid block whose commitment seals are then stripped to construct the adversarial test input. Network transport has no access to signing operations.
- The receiver uses **shipped QBFT defaults**, production 5-second allowed future-time window and genuine Ethereum/66 networking.
- Two independent, persistent LevelDB databases on an isolated **256 MiB ext4 loopback filesystem** are initialized with the same genesis and directly compared after importing the identical canonical block. Only the network database connects to adversarial peers.
- Allocations use Linux file `st_blocks * 512` (actual allocated disk blocks), not message sizes. Attacker-sent bytes, application responses, process aggregate CPU and session wall time are measured separately.
- No public or third-party network nodes were targeted.

## Instrumented matrix — passing expanded execution

| Scenario | Actual evidence | Ingress/egress in tested peer | Persistent disk delta |
|---|---|---:|---:|
| Canonical positive control | ETH66 block import succeeds; identical direct import | 1 canonical body response | **+4,096 B** each |
| Invalid 2-of-4-QBFT `NewBlockHashes` announcement | Sent; automatic fetcher requested **0** headers within 450 ms | 36 B sent | **0 B** |
| Invalid 2-of-4-QBFT `NewBlock` propagation | Sent; no canonical replacement detected within 450 ms | 890 B sent | **0 B** |
| Explicit `RequestOneHeader(invalidHash)` | ETH66 request triggered, exact invalid header delivered, shipped QBFT verifier rejected 2/4 committed seals | 788 B reply; 1 header request | **0 B** |
| Explicit `RequestBodies(invalidHash)` | ETH66 request triggered, one correctly decoded transaction body delivered **only to diagnostic sink**, no importer call | 125 B reply; 1 body request | **0 B** |
| Explicit matching `RequestNodeData` | 1 requested 32 KiB arbitrary node returned; dispatcher delivered to diagnostic sink | 32,786 B reply | **0 B** |
| Two nodes returned for one requested hash | ETH66 requested-items bound rejected response; peer disconnected | 65,559 B reply | **0 B** |
| BlockBodies packet to NodeData request ID | Mismatched response type rejected; peer disconnected | 11 B reply | **0 B** |
| Three unsolicited NodeData responses | Three new peer identities, each sent an unsolicited 65,557-byte reply; each peer disconnected | 196,671 B sent | **0 B** |
| Full compaction and database restart | Canonical head=1, receipt intact, invalid block absent | N/A | **28,672 B** each |

The unsolicited NodeData request IDs are never registered. The matching and overlimit cases establish **different protocol-control branches**: the dispatcher delivers a matching typed response, rejects excess data for the requested item count and rejects a response whose type disagrees with the outstanding request.

The **2-of-4** verifier rejection is observed on the exact **header delivered over ETH66** in the new matched-header test, not inferred solely from the source or the pre-network verifier check. The matched body is only a transport/decoding control; it is not evidence of importing a block with invalid commitments.

## Peer churn costs — bounded, descriptive, not capacity proof

- **Ten separate malicious peer sessions**, each explicitly disconnected and torn down, covering two announcement/propagation cases, two matched noncanonical header/body requests, three node-data request variants and three unsolicited node-data injections.
- **Total measured session wall-time:** `964,620 µs` (about **965 ms**), **including 450 ms deliberate dwell in each** of the announcement and propagated-block scenarios. This is *not* pure handshake or disconnection latency.
- **Aggregate process user+system CPU during session windows:** `44,239 µs` (about **44.2 ms**). CPU timing includes unrelated goroutines/GC and cannot be attributed solely to the adversarial peer.
- **Direct injected bytes:** `197,597 B` (excludes responses to legitimate diagnostic requests).
- **Total peer outbound bytes including responses:** `296,866 B`.
- **Persistent allocation during all ten peer sessions:** **0 B**; **all 10 connections detached**.
- The eight scenarios without deliberate 450 ms dwell each finished in approximately **4.2–8.3 ms**, including connection, transport, processing, cleanup, and measurement. Treat as runner-specific observations; no statistical performance baseline or production TPS extrapolation.
- Filesystem free space before and after experiment: **229,072,896 B** to **229,007,360 B**. The **65,536 B** used includes both legitimate test databases, their shutdown allocations and filesystem overhead. The test never approached disk exhaustion.

**Disk reconciliation:** pre-compaction, both network and direct import occupied **20,480 B**. Explicit compaction left both at **20,480 B**. Closing and reopening the persistent databases increased each to **28,672 B** (legitimate database shutdown/recovery state), still **exactly equal**. The persistent excess attributable to these lower-authority cases is **0 B**.

## Implementation evidence & mechanism

- Certified `eth/protocols/eth/handlers.go`: `handleNodeData66` splits an ETH66 response envelope into request ID and RLP payload; it calls `peer.dispatchResponse`. Only a matching pending request triggers `decodeLimitedList` with `requestedItems(req)`. The protocol handler does **not** write a received node payload directly to LevelDB.
- Certified `eth/protocols/eth/dispatcher.go`: matching request IDs and message types are checked before dispatch; an unknown/unsolicited ID maps to a dangling-response error. A wrong response type is rejected. The source includes a limited stale-request-ID exception for locally cancelled requests.
- Certified QBFT backend `VerifyHeader`: the exact delivered 2/4-committed-seal header fails `invalid committed seals`. A valid 3/4 header/body remains the trusted positive control.
- The scenario with a matching NodeData reply tests **explicit diagnostic `RequestNodeData`**, **not** production fast-sync, snapshot-sync or a trie importer. This distinction is critical: decoding a 32 KiB node and intentionally not storing it cannot prove the safety of a state-sync ingestion path.
- Invalid `NewBlockHashes` advertisement did not trigger an automatic header request within its 450 ms observation window. This is an **unreached downstream stage**; it cannot support a claim that the automatic block-fetcher validated or rejected the header. The explicit matched header-request case closes the *transport/consensus* gate but not that automation gap.

## Quality gates & disposition

| Gate | Result |
|---|---|
| G1 immutable source identity, no target modifications | PASS |
| G2 actual p2p ETH66 network and positive canonical import | PASS |
| G3 zero attacker validator signing authority; 2/4 hostile QBFT input | PASS |
| G4 actual network-delivered invalid header/body on matching requests, invalid seal rejection | PASS, diagnostic request path only |
| G5 matched, overlimit, wrongtype and unsolicited NodeData response variants | PASS, protocol/control level |
| G6 bounded peer-churn time, process CPU, transmitted bytes, independent physical LevelDB allocation, compaction/restart | PASS |
| G7 evidence of healthy-disk exhaustion, remote validator termination, third-party economic impact or consensus bypass | **NOT ESTABLISHED** |

**Classification:** VERIFIED NEGATIVE STORAGE-AMPLIFICATION CONTROL. **Not bounty-ready.**

### Limitations and next test

The experiment ran **ten isolated sessions**, not a statistical high-throughput fuzz campaign. Announcements were observed for **450 ms**; no header fetch was triggered in that window. The test does not exercise Snap/1 snapshot state importer, `snap` range proofs, remote state-sync data inserted into the trie/DB, or unsolicited peers injecting mutable finalized QBFT commitments. It does not quantify steady-state CPU under concurrent attacker connections or packet floods, and the tested peer does not gain validator status. Per-session `runtime.MemStats.HeapAlloc` deltas include garbage-collector variability and must not be interpreted as peak resident memory.

**Next qualified hypothesis (P2m):** Target a real **state-sync/trie persistence path** with a legitimate outstanding request and an adversary-controlled yet unauthenticated response, verify cryptographic hash/trie-proof checks, compare durable allocations and compaction against an identical valid-node baseline, and require measured excess allocation or a process-level fault that actually meets bug-bounty scope. Keep all campaigns isolated to local nodes and preserve source immutability.

No vulnerability is promoted solely from a packet being transmitted, a malicious peer being dropped, transient CPU consumption, or a local ENOSPC that predates the remote peer's contact.
