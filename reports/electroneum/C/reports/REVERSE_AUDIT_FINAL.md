# Electroneum Reverse Audit R — Final 14/14 Disposition

**Date:** 4 November 2026. **Mode:** additional live reverse audit, not scheduled/hourly. **Traversal:** newest unresolved E → older E → D → C → B → A. **Ownership:** independent R-only files under `reports/electroneum/C/reports/`, `reports/electroneum/C/reverse/`, and `.github/workflows/electroneum-reverse-independent-ci.yml`. Existing A–E reports, fixtures, workflows and automations were not intentionally edited by R.

## Executive result

The reverse queue is **14/14 complete**. R independently reproduced multiple target-runtime software defects, but **did not establish an attacker-reachable remote asset-theft, consensus-finality, native-supply or historical-rewrite vulnerability**.

The strongest demonstrated implementation defect remains **C-002**: exported `KeyStore.Import` can propagate malformed encrypted-JSON panics and an unrecovered invocation terminates the Go test process. The default externally exposed RPC path for arbitrary encrypted keyfile JSON was not found.

Three E-class API correctness defects were reproduced under controlled inconsistent-backend/reorg states: nil-header receipt panic, silent incomplete log ranges, and a receipt-response canonicality TOCTOU. A separate E numeric representation defect truncates gas price to 64 bits, but default fee admission materially defeats the tested production scenario.

QBFT contains real round-width defects at 2^32, 2^63 and 2^64. The actual ROUND-CHANGE handler, however, applies a full-width current+15 admission bound before the lossy conversions. F+1 distinct validator attempts at each huge round were rejected in certified runtime. The 2^32 signing-domain alias is therefore real but not demonstrated reachable through normal authenticated consensus transitions.

A-class fee/priority-cache and supply hypotheses were challenged with a real synthetic registry contract and real EVM execution. The tested success, EVM-revert, core-error rollback, London burn/tip and gas-waiver cases behaved correctly.

## Certified target

| Item | Identity |
|---|---|
| Windeep immutable source commit | `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` |
| Source tree | `de7f3c75a2db7e87a89918f1257820703d5b731e` |
| Pinned Electroneum upstream | `3aeb14db0d6384243302f3a025bdff904dc28bf6` |
| Historical archive provenance SHA-256 | `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` |

All decisive R Go tests copied the certified source into disposable runner scratch. Scratch-only defensive mutations were used only as sensitivity controls and immutable-source hashes were rechecked. No public chain, real wallet secrets or validator network was attacked.

## Final 14-item matrix

| # | Candidate | Final R disposition | Decisive CI |
|---:|---|---|---|
| 1 | E-RPC-010 receipt nil header | **Verified conditional software defect; remote reachability open** | [41742642862](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41742642862) |
| 2 | E-RPC-008 incomplete log range | **Verified conditional software defect; production missing-header reachability open** | [41743587384](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41743587384) |
| 3 | E-RPC-004 receipt canonicality/reorg | **Verified rawdb-backed TOCTOU discrepancy; production adversary reachability open** | [41744841662](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41744841662) |
| 4 | E-RPC-002 gas-price width | **Verified numeric truncation; default fee-cap counterexample blocks tested exploit** | [41745455574](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41745455574) |
| 5 | D partial receipt/retry | **Defensive behavior passed; realistic crash/pivot restart remains open** | [41746346715](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746346715) |
| 6 | D header rollback/restart | **SetHead/restart/reimport passed; finalized-marker discrepancy remains conditional** | [41746803595](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746803595) |
| 7 | D receipt wire differential | **Wire/decoded commitment equivalence passed** | [41747025272](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41747025272) |
| 8 | C-002 malformed keystore import | **Exported-import panic and unrecovered process failure confirmed; default remote path not found** | [41747899973](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41747899973) |
| 9 | C-001 wallet mnemonic return | **Default remote secret-leak hypothesis disproven; explicit `personal` exposure remains admin risk** | [41748823191](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41748823191) |
| 10 | B 2^64 round state alias | **Low-level alias verified; F+1 handler admission blocked** | [41749154241](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41749154241) |
| 11 | B 2^63 signed reconstruction | **Signed reconstruction defect verified; handler admission blocked** | [41749154241](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41749154241) |
| 12 | B 2^32 seal domain | **Signing-domain alias verified; immediate F+1 admission blocked** | [41749737953](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41749737953) |
| 13 | A-FEE-07 priority-cache parity | **No defect reproduced in success/revert/core-error boundaries** | [41750891833](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41750891833) |
| 14 | A-FEE-04/05 burn/waiver supply | **No supply defect reproduced in ordinary/revert/waiver controls** | [41750891833](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41750891833) |

## Reproduced defect families retained for engineering action

### C-002 — exported encrypted-keystore parser panic

The actual exported `KeyStore.Import` boundary was tested, not only internal KDF parsing. Valid encrypted key import succeeded. Missing salt, numeric salt and invalid AES-CTR IV produced panics. Unsupported cipher and invalid MAC hex returned controlled errors. A strict fail-closed test deliberately rejected the original source; a scratch-only typed salt guard converted the missing-salt panic into a structured error. An unrecovered import invocation exited the Go test process with the `KeyStore.Import` stack.

**Security boundary:** arbitrary encrypted-keyfile JSON is not accepted by the default external HTTP/WS RPC methods inspected; `personal_importRawKey` imports a raw private key, not encrypted keystore JSON. The demonstrated risk is therefore local/application ingestion unless a custom service exposes this function.

**Engineering priority:** high for robustness. Validate every KDF field type/range, enforce `len(derivedKey)>=32`, validate AES IV length, cap KDF resource parameters, and return errors rather than panics.

### E-RPC-010 — receipt handler nil-header panic

The real `PublicTransactionPoolAPI.GetTransactionReceipt` panicked when a London receipt/transaction remained available but `HeaderByHash` returned `(nil,nil)`. Normal coherent London, no-receipt and pre-London controls passed. A scratch-only guard changed the panic to a structured error and made the strict oracle pass.

**Security boundary:** a remote client controls the transaction hash query but has not been shown able to force a coherent full node into the required receipt-present/header-missing state.

**Engineering priority:** straightforward defensive fix. Check `header != nil` and `header.BaseFee != nil` before dereference.

### E-RPC-008 — silent incomplete `eth_getLogs`

The real unindexed `Filter.Logs` returned one log from a three-block requested range with **nil error** when the middle header was synthetically missing; a missing first header returned an empty successful result. Explicit backend errors propagated correctly. A scratch-only nil-header error guard made the strict fail-closed oracle pass. A similar source pattern exists in indexed scanning.

**Security boundary:** ordinary canonical full nodes should have contiguous canonical headers. A lower-trust caller has not been shown able to create the gap.

**Engineering priority:** return an explicit incomplete-range error on `(nil,nil)` header lookup in indexed and unindexed paths.

### E-RPC-004 — receipt canonicality TOCTOU

Using rawdb-backed synthetic chain state, stable canonical and missing-data controls passed. A forced canonical flip during the receipt query allowed a stale successful orphan receipt response before a post-read canonicality check. A scratch-only canonical recheck made the strict oracle pass.

**Security boundary:** controlled reorg timing was injected locally. No QBFT adversary has been demonstrated able to deterministically win this race or cause exchange credit.

**Engineering priority:** revalidate transaction/block canonicality after receipt/header reads before returning externally relied-upon success.

### E-RPC-002 — gas-price narrowing

A signed synthetic transaction with gas price `2^64 + 12345` was represented in receipt JSON as `12345` in both London and pre-London characterization because a full-width integer is narrowed through `Uint64()`.

**Counterexample:** default transaction fee caps make the tested huge gas price economically/admission-wise unrealistic for a standard 21,000-gas transaction. This is a representation defect, not demonstrated exploit.

**Engineering priority:** use full-width JSON quantity representation if protocol-valid values can exceed uint64; otherwise explicitly enforce the width at transaction admission so serialization and protocol domains match.

### D finalized-marker discrepancy

Ordinary `SetHead` rewind, process restart, honest reimport and corrupted commitment rejection behaved correctly. The reverse ledger retains a narrower finalized-head/DB-marker discrepancy as a conditional candidate. It has not been tied to a reachable QBFT attacker path or historical rewrite.

**Engineering priority:** align finalized marker/head persistence with explicit rewind semantics and add restart/finality tests before severity assignment.

### B QBFT round-width family

Three real implementation-width behaviors were independently reproduced:

- `roundChangeSet` uses `Uint64()`, so direct rounds 0 and 2^64 alias.
- unsigned key 2^63 reconstructed through `int64` becomes `-9223372036854775808`.
- committed-seal header/signing domain uses 32-bit round representation, so round-0 signatures verify after a synthetic `CommitHeader(..., 2^32)`.

Controls are strong: the actual `handleRoundChange` compares full-width rounds against current+`MaxFutureRoundGap` = **15** before the lossy storage path. With a four-validator set, F+1=2 distinct validator-source attempts at 2^32, 2^63 and 2^64 were all dropped. Round 0/1 signing domains were distinct and round-1 signatures did not verify against the encoded round-0 domain.

**Engineering priority:** enforce an explicit protocol maximum below every lossy width and replace signed reconstruction. Changing committed-seal encoding is consensus-breaking and requires coordinated protocol version/fork handling.

## Falsified or healthy paths

### C-001 default remote mnemonic leak

The exact default-remote-leak hypothesis did not survive testing. Unknown/unsupported wallets returned empty results with errors. `personal` is registered private and absent from default HTTP/WS modules. RPC callback errors and panics did not serialize mnemonic-shaped results. A synthetic mnemonic returned only when the callback succeeded, matching documented smartcard initialization behavior.

Explicitly enabling `personal` over HTTP/WS is still dangerous operator configuration. `InitializeWallet` also lacks the explicit external-RPC guard used by `UnlockAccount`, so hardening remains reasonable, but no unauthorized smartcard initialization was reproduced.

### D receipt transport/retry

Peer revocation, replay, invalid RLP, reset/expiry, full receipt retry, header rewind/restart, honest reimport and wire/decoded receipt-root equivalence survived the tested reverse controls. These tests materially weaken simple historical-corruption hypotheses.

### A priority registry/cache

The real EVM registry fixture returned a valid priority list on `getTransactors` while an ordinary empty-data registry transaction deliberately reverted. The reverted transaction produced a failed receipt with nil core error, then the priority cache was rebuilt from reverted EVM state and retained the correct authorized key. A successful target transaction also refreshed correctly. An intrinsic-gas core error followed by miner-style snapshot rollback preserved the non-journaled cache because the cache was not changed before the core error.

This defeats the tested cache-rollback/parity allegation. A full signed miner-vs-import block-construction differential would add coverage but is not justified as a defect based on present evidence.

### A London supply, burn and waiver

Certified independent ledger results:

- ordinary transaction: gas `21000`, base-fee burn `168000`, miner tip `42000`;
- EVM-reverted transaction: gas `21006`, burn `168048`, tip `42012`;
- priority gas-price waiver: gas consumed but **zero sender/miner fee delta**;
- waiver transaction with nonzero fee fields: rejected.

No supply creation, missing burn or miner over-credit was reproduced.

## Evidence-quality rules applied

1. A failed CI configuration, YAML parse, fixture compile error or incorrect assertion was never counted as an Electroneum defect.
2. A characterization test marked PASS can still demonstrate unsafe target behavior; the actual assertion/marker was inspected.
3. A source discrepancy was not promoted without actual certified Go execution where practical.
4. Synthetic-backend reachability was separated from shipped full-node reachability.
5. Scratch defensive mutations proved oracle sensitivity only; they were not represented as deployed patches.
6. Component defects were not equated with system exploitability.
7. No confirmed security disclosure was created merely from a parser panic, arithmetic collision or mock inconsistency.

## Recommended engineering order

1. **Keystore parser hardening (C-002):** small, local, high-confidence robustness fix; prevent panics at exported import boundary.
2. **RPC fail-closed guards (E-RPC-010 / E-RPC-008):** inexpensive checks that convert ambiguous/panic states into explicit errors.
3. **Receipt canonicality revalidation (E-RPC-004):** important for exchange/explorer correctness if reorg race is feasible.
4. **QBFT width cleanup:** define protocol round domain; avoid lossy conversions. Coordinate any signed-domain format change as a protocol upgrade.
5. **Finalized-marker rewind semantics:** clarify and test expected persistence behavior.
6. **Gas-price serialization width:** align RPC encoding with the actually admissible transaction-value domain.
7. **No A economic code change based on R evidence:** tested fee/burn/cache controls behaved correctly.

## Final security conclusion

**Verified software defects exist. Confirmed remotely exploitable security vulnerabilities from this reverse campaign: 0.**

The highest-confidence harmful behavior is the exported malformed-keystore panic/process-failure path, but its default remote attacker path remains absent. E API defects can produce panic/incomplete/stale/narrowed responses under injected state inconsistencies, but production attacker control remains to be demonstrated. QBFT width defects are real, while current authenticated round admission blocks the tested huge-round paths. D and A defensive/economic paths largely survived independent counterexample testing.

Further work should therefore stop broad fuzz repetition and concentrate on **production reachability** for the retained defects: real full-node reorg/header availability boundaries, actual application keyfile ingestion, and operational finalized-marker behavior.
