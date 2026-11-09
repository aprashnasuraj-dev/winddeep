# TransferWise Lane C — Code execution and unsafe data flow

2026-11-09 follow-up: ranked three scoped hypotheses: (1) `transferwise/neural-lifetimes` git metadata callback subprocess argument handling, (2) its model checkpoint loading boundary, (3) `transferwise/pipelinewise-singer-python` test-only evaluation. Selected (1) for immediate, inexpensive negative-control falsification.

Target: `transferwise/neural-lifetimes@cb26a34b12ba634aa6b5b34853a66166c47b0ea1`, `neural_lifetimes/utils/callbacks/git.py`. The callback executes fixed `git` argv arrays without a shell; the branch name is returned as data and is not interpolated into an executable command. A local isolated Git fixture tested an inert punctuation-containing branch and ordinary `master` control: both returned exact names with exit 0. This is an analogous boundary control, **not target-runtime execution**. No attacker-controlled execution sink, shipped Wise-specific exploit path, or concrete impact established. NOT REPORTABLE.

Environment: Python 3.13.5, git 2.47.3 available. Isolated winddeep checkout absent. Exact `python scripts/audit/transferwise_workspace.py doctor --check` failed with `can't open file '//scripts/audit/transferwise_workspace.py': [Errno 2] No such file or directory`; `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git refs/heads/transferwise` failed with `Could not resolve host: github.com`. Thus checkout-based target reproduction is ENVIRONMENT_BLOCKED. G0 fail (external attacker entry not established); G1 partial (source pinned, Wise deployment relevance unverified); G2 fail (no target PoC); G3-G4 unmet. No submission ZIP or Library delivery.

Previous YAML configuration hypothesis remains retired and should not be repeated without new reachability evidence.

Next decisive step: restore isolated checkout/source materialization, run workspace doctor, then prioritize a different scoped external-input-to-sink hypothesis. Never infer target execution from connector inspection or synthetic fixtures.
