# C-005 — Genesis and chain-config activation assessment (2026-11-06 14:34 NPT)

**Decision: DISPROVEN within shipped built-in genesis/default chain configurations at ordinary heights; BLOCKED for independently verified live deployment and runtime behavior. NOT REPORTABLE.**

## New source evidence (this investigation)
Read immutable source at certified repository commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` via GitHub connector:
- `vendor/electroneum-sc/params/config.go:46-63,79-96,111-128`: mainnet, stagenet, testnet all set `FutureForkBlock = big.NewInt(math.MaxInt64)`.
- `vendor/electroneum-sc/core/genesis.go:448-466,480-499,506-511`: `DefaultGenesisBlock`, `DefaultTestnetGenesisBlock`, `DefaultStagenetGenesisBlock` explicitly select their corresponding built-in chain configs. Thus the built-in genesis constructors do not override the disabled-fork default.
- `vendor/electroneum-sc/core/genesis.go:228-305`: `SetupGenesisBlockWithOverride` uses default genesis for an uninitialized DB when genesis is nil; accepts custom genesis when supplied; for existing non-mainnet private networks with nil genesis, retains stored chain configuration. Its two explicit overrides are ArrowGlacier and terminal total difficulty, not FutureForkBlock.
- `vendor/electroneum-sc/params/config.go:242,408,543-544`: FutureForkBlock is JSON-serializable and fork activation uses `IsFutureFork`; configuration compatibility checks compare it. A custom genesis or pre-existing stored config is a legitimate counterexample to claiming fork activation is *impossible everywhere*.

## Observed versus expected
Expected under shipped built-in mainnet/stagenet/testnet genesis: no pre/post future-fork transition at ordinary heights. Observed source trace confirms all three genesis constructors inherit MaxInt64. The earlier `TxPool.reset` reinjection-before-fork-flag-update ordering remains a source observation but cannot produce an ordinary-height default-chain fork transition.

## Attacker model and severity
A remote unprivileged sender cannot choose the chain's genesis configuration or schedule a fork. A custom genesis/chain-config override is an operator-controlled prerequisite, not an attacker-controlled input by default. No demonstrated P1/P2 consequence, no accepted invalid signature, no unauthorized debit, no victim balance difference. Strongest counterexample to global disproof: a separately configured deployment may activate FutureForkBlock, requiring independent config evidence and runtime admission-vs-execution proof.

## Execution accounting
New operations: immutable GitHub source reads of `core/genesis.go` and `params/config.go`, including exact line windows, successful. No certified bootstrap or Go target-runtime test executed; target command/exit code N/A. No independent ledger oracle, three repetitions, CI dispatch, or mutation experiment. Certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned commit `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive SHA-256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` are historical certification metadata, not fresh bootstrap proof. E1 source inspection only; E2/E3/E4 absent.

## Decision and next discriminating action
Close C-005 for default-chain future-fork activation, defer custom-deployment scenario absent evidence of an attacker-reachable P2+ mechanism. Rotate to an already existing default-reachable signing/nonce fixture on a certified runner; first verify no Class C run is active. No external vulnerability report is warranted.
