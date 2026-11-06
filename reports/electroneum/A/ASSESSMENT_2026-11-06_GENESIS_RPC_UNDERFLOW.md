# Class A internal assessment — A-REWARD-GENESIS-RPC-01
Date: 2026-11-06 NPT. Decision: SUSPECTED, NOT REPORTABLE (E1 only). Hypothesized P4 only if an exposed RPC request demonstrably causes consequential availability degradation; P1/P2 network halt NOT established. No CVSS assigned.

## Certified source and scope
Immutable source commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0; tree de7f3c75a2db7e87a89918f1257820703d5b731e; pinned upstream 3aeb14db0d6384243302f3a025bdff904dc28bf6; provenance archive SHA256 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b. Source was read through GitHub at immutable commit; **no fresh certified bootstrap or Go target runtime execution this invocation**.

Source: `vendor/electroneum-sc/consensus/istanbul/backend/api.go`, `API.GetBaseBlockReward` accepts an explicit block number, permits block 0 whenever the current height is >=0, obtains the canonical genesis header, and calls `Backend.GetBaseBlockReward(..., nil)`. `engine.go`, `Backend.GetBaseBlockReward` computes `header.Number.Uint64()-1` and calls `sb.emission(chain, number, header.ParentHash, nil)`; on emission error it panics. `Backend.APIs` registers namespace `istanbul` with `Public: true` (actual network exposure depends on RPC module allowlists). `sb.emission` returns ErrUnknownAncestor if the expected parent header is absent, but may instead return cached/checkpoint emission; the precise genesis call result requires a real runtime test.

## New executed independent boundary oracle
Command: `python - <<'PY' ...` (Python 3 integer model; exact logic `(height-1)&((1<<64)-1)`); exit 0, output:
```
height=0, parent_uint64=18446744073709551615, wraps=True
height=1, parent_uint64=0, wraps=False
height=2, parent_uint64=1, wraps=False
oracle=PASS
```
This confirms only unsigned-underflow arithmetic, **not** that a live RPC request panics, crashes the process, or impacts availability. No synthetic target runtime was executed.

## Expected, observed, attacker route, and strongest counterexample
Expected: querying the reward for canonical genesis should return a defined reward or structured RPC error without crashing the node. Observed: source-level unsigned underflow in the parent height at block 0; runtime outcome UNOBSERVED. Potential ingress: an unauthenticated RPC client only when `istanbul` is exposed by the node configuration; no valid malicious canonical block is necessary for this API hypothesis. Strongest counterexamples: (1) namespace not enabled externally; (2) emission may find a checkpoint/cache despite wrapped height; (3) RPC panic recovery may convert a panic into an isolated request error rather than process/network DoS. Thus no demonstrated security impact, no P-band assigned.

Separate consensus-path claim: a valid non-genesis canonical header has a valid parent, and `emissionApply` passes a nonnil circulatingSupply to `GetBaseBlockReward`, bypassing its parent lookup; an invalid/missing parent is not a valid remote consensus exploit. No network halt established.

## Next discriminating test
On certified immutable source, construct an isolated in-process RPC server with a valid genesis and explicit `istanbul_getBaseBlockReward(0)`; run honest height 1/2 and genesis 0, verify exact response/panic recovery, process liveness and repeated requests, then check default RPC module exposure. Do not report until E2–E4 and credible security impact. No external report created. No production traffic or secrets used.
