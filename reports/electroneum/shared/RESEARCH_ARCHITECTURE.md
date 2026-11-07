# ETN-SC Coordinated Adversarial Research — Architecture v1 (2026-11-07)

## Executive contract

Five hourly investigators A–E share **one certified immutable Electroneum source**, a single executable regression matrix and cross-lane handoffs. No one should repeat local Git/DNS troubleshooting. Local Git is **not a worker prerequisite**: source inspection and branch changes use the authenticated GitHub connector; only a sandboxed GitHub Actions job performs the necessary pinned checkout and `tools/electroneum_target_bootstrap.sh`. Do not disable certificate/tree verification.

### Division of responsibility and trust boundaries

| Owner | Security invariant | Externally controlled input | Required end-to-end proof |
|---|---|---|---|
| A | No unauthorized native value issuance, credit, loss or reward | Signed transactions or consensus-admissible blocks | Exact state deltas across accepted canonical blocks and independent supply ledger |
| B | Attacker below validator threshold cannot finalize invalid history or stop honest quorum | Authenticated validator/P2P message and peer timing | Valid signed N=4/F=1 network fixture, safety/liveness oracle and measurable effect |
| C | Only authorized owner signs/spends; no cross-domain replay | Signed/malformed transactions or *default-exposed* RPC | Unauthorized spend/signature verified against actual transaction/block admission, not just recovered sender |
| D | Remote peers cannot rewrite canonical history or permanently disable recovery | Headers, receipts, snapshots, peer responses | Honest chain A, adversarial sibling B, actual verification/restart and canonical outcome |
| E | Default RPC cannot materially falsify financially relevant canonical state | Default external RPC and consensus-valid transaction | Accepted canonical receipt via public RPC plus affected independent consumer decision |

## Executable system now available

- `shared/adversarial_matrix.json`: explicit probe-to-owner coverage contracts; labels component-only vs canonical semantics.
- `shared/run_adversarial_matrix.py`: verifies certified source identity, copies read-only source into disposable scratch, installs Go fixtures, runs **actual target Go tests** with `-count=3`, validates honest/negative-control markers, and emits per-probe stdout, log hashes and `result.json`.
- `shared/test_signed_sequence_test.go`: new **cross-component** signed transaction sequence (honest nonce0, duplicate nonce replay, wrong chain-ID, insufficient balance, honest nonce1) with actual `ApplyTransaction`, state nonce, sender/recipient/miner, gas burn and conservation checks.
- `.github/workflows/electroneum-adversarial-matrix.yml`: five parallel certified Go lanes, isolated CI artifacts retained 14 days. The actual CI job conclusion and artifact must be inspected; a triggered workflow is NOT a passing test.

The shared matrix is a **regression harness**, not a vulnerability finder by itself. Its coverage establishes E2 at best. Even if all tests pass three times, nothing E3/E4 is proven: no attack succeeded. This distinction is mandatory.

### Attack exploration (not repeated exhaustive fuzzing)

1. **Map reachable boundary:** public version/config, real default exposure, trust boundary, attacker privileges, relevant upstream patch differential.
2. **State hypothesis:** name a falsifiable security invariant with honest, malicious and strongest defensive counterexample.
3. **Construct a valid adversarial state machine:** use real signed transactions, validator signatures, actual `InsertChain`/`ValidateState`/RPC paths or deterministic peer simulation. Avoid fabricated permissions and mock-only exploit claims.
4. **Run a decisive target experiment:** reuse existing fixture, then vary sequence/nonce/round/fork/state/root; save raw output, exit status, commit and independent oracle. A source match is not runtime.
5. **Adjudicate:** E1 source -> E2 actual certified path -> E3 three distinct fresh-state invariant breaches -> E4 genuinely attacker-reachable P1/P2/P3 consequence. Disprove or close if defenses hold.
6. **Escalate confirmed P1–P3:** publish a self-contained report using *public* Electroneum code and fixtures only. Another expert must reproduce from a clean public tag/commit.

Give a promising lead adequate runtime if the test can genuinely discriminate it. **Do not arbitrarily stop at 10 minutes**; cap unstructured fuzzing and prohibit re-running without new material input. Two repeated *identical* unproductive attempts trigger a changed plan, not automatic abandonment of a credible lead.

## Research queue, ownership and avoiding five independent loops

Each worker maintains `reports/electroneum/<class>/CANDIDATE_FINDINGS.md` and `LATEST.md` only. Before each run, inspect all five latest verdicts and `shared/HANDOFFS.md`, plus the shared matrix. Fingerprint leads by **public file:function, attacker interface, invariant, and demonstrated state precondition**; collision means handoff, not a duplicate expensive run. The common matrix defines executed coverage; closed leads are not silently reopened.

Each lead must have: ID, class owner, public source file:function, shipped/default exposure, attacker-controlled input, hypothesized P-band, E1–E4 evidence, strongest counterexample, one next discriminator, last test run/commit, and status NEW / TESTING / CONFIRMED / DISPROVEN / DEFERRED / DUPLICATE / BLOCKED. No CVSS without a real effect. There is no mandated daily finding quota, but token commits and no-new-evidence hours are not legitimate investigations.

**Coordinator without shared-file collisions:** shared files are maintained as versioned infrastructure. Workers read these files, write class-owned tests/candidate records, and propose cross-class additions in class-owned handoffs. A coordination update to shared infrastructure must first reread current head and serialize its writes; ordinary A–E invocations never concurrently rewrite the same manifest.

## CI and resource policy

New shared CI is the automatic regression lane. Historical A–E long fuzz workflows are retained for **manual, focused follow-up**, not automatically dispatched from every documentation/test change. Do not dispatch identical jobs while a healthy run is active. No public node calls, production funds, destructive DoS or real private keys. Only in-process synthetic fixtures, isolated permissioned networks and bounded resource tests.

Large fuzz campaigns can consume 5 × 300 runner-minutes and still have no reachability proof. For a change in hypotheses, start with one discriminating signed case. Expand duration only when coverage/proof gap and kill criteria are explicitly recorded, and stop on falsification.

## Submission format, independent of the research workbench

For **E4 only**, create five numbered sections:
1. **Findings** — verified title, real preconditions, default-shipped affected version, CVSS vector/P1–P3 mechanism.
2. **Steps to reproduce** — exact public upstream checkout/tag, prerequisites, standalone fixtures, commands, expected vs observed, honest/malicious/boundary cases, three independent fresh-state reproductions and cleanup. **No private workbench terms or dependencies.**
3. **Independent proof logs / proven logic** — sanitized real stdout/stderr, checksums, state/cryptographic oracle, exit codes, measured vs derived distinction.
4. **Affected code / sources / paths / actual evidence** — public immutable source URLs and line numbers, call chain and broken invariant.
5. **Remediations** — patch logic, tests, backward compatibility and configuration concerns.

If only E2 component behavior is shown, keep it INTERNAL and explicitly mark remaining E3/E4 gap. State the strongest counterexample; e.g., a successful signed transaction **does not** imply a consensus-valid block, and a field truncated in a mock RPC adapter **does not** imply exchange loss.

## Next engineering gate

The current signed state-machine fixture and existing class fixtures are regression baselines. The **next new hard capability** should be a certified IBFT validator/test-chain harness that exercises actual consensus-valid canonical insertion with synthetic signatures; then wire real RPC on that chain. Do not call such a harness complete until CI shows honest accepted and crafted case rejected/accepted as intended, followed by independently replayed state/output.

