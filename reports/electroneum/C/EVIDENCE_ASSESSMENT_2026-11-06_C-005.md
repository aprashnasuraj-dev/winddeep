# Internal evidence assessment — C-005 — 2026-11-06 11:27 NPT

**Decision: DISPROVEN at source-path level for the proposed *missing fork-aware priority-signer selection in pool admission* mechanism; overall Class C vulnerability NOT CONFIRMED. E1 only. SIMULATION_NOT_EXECUTED.**

## Boundary and independently read source
Actor Y0 sends a priority transaction through the normal transaction pool; hypothetical effect is accepting a pre-fork priority signature after the future fork and thereby misclassifying authorization. The certified immutable source commit is `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certificate tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These are certificate identities; no current bootstrap verified them.

- `core/types/transaction_signing.go:48-63` MakeSigner selects NewFutureForkSigner at the configured fork; `:74-87` LatestSigner does not select that future signer, motivating the hypothesis.
- `core/tx_pool.go:318` initializes ordinary pool.signer with LatestSigner; **but** `:654-665` defines prioritySigner(), which selects NewFutureForkSigner when pool.futureFork is true.
- `core/tx_pool.go:703-717` validates the ordinary sender with pool.signer and separately validates priority signatures with **pool.prioritySigner()**, rejecting invalid signatures and unknown registered priority keys.
- `core/tx_pool.go:1473-1477` updates futureFork using the next pending block height.
- `core/types/transaction_signing.go:191-228` both sender and priority-sender caches compare signer.Equal before reuse.

## Competing explanations / counterexample
H1: LatestSigner omits the future signer, so pool accepts a priority signature that the execution signer rejects. H2: A dedicated prioritySigner bridges that difference. H3: A fork-transition race exists despite the dedicated signer. **Source evidence supports H2 and defeats H1's claimed missing-check mechanism.** H3 remains untested, especially timing around reorg/reinjection and cache updates. No actual malicious transaction acceptance, balance change, secret disclosure or victim impact was observed.

## Expected vs observed and execution ledger
Expected: post-fork priority signatures are checked under sender-bound rules; pre-fork signature reuse is rejected post-fork. Observed: explicit fork-aware selection and cache invalidation in source; **no runtime accept/reject observed**. Connector fetch_file immutable source succeeded (two source files and focused ranges). Local command `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` exit 128, DNS resolution failure. Local bootstrap NOT RUN, Go tests 0, independent oracle 0, mutation-sensitivity 0, CI newly dispatched 0. No class CI status on historical commit `7454f86010f3467a0baac2a9fa4b967d090b5699`; active-run inventory remains UNKNOWN. Historical CI is not evidence for C-005.

## Missing proof and next discriminating test
Run a **single** certified-runtime synthetic fork-boundary transaction-pool test: valid sender + priority signatures at N-1/N, sender-signature mutation after priority signing, invalid priority key, and sender cache primed under the pre-fork signer. Assert pool admission and block execution agree; use independent expected sender/key and scratch-only weakened prioritySigner control. Do not call source-only protection a V3 disproof or general security proof. No external vulnerability report created.
