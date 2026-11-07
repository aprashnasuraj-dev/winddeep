# ETN A-E fresh-process evidence gate v2

This integrates an additive runner into the existing certified Electroneum Go CI matrix. It does not modify the certified target source or call public chain nodes.

- Existing native runner: reports/electroneum/shared/run_adversarial_matrix.py.
- Fresh isolation runner: reports/electroneum/shared/run_fresh_matrix.py.
- Offline unit test: tests/etn/test_run_fresh_matrix.py.
- Three separate native Go runner processes and scratch source copies per class.
- SHA-256 logs, exact test PASS counts, marker counts cross-checked against actual logs, fixed fixture SHA across attempts.
- GitHub Actions event SHA must match the checkout; certified tree must match immutable source.
- Timeout kills the process group, avoiding orphaned long-running Go children.
- CI uploads only fresh-evidence.json, fresh-*/result.json, fresh-*/*.log and B patch logs/JSON. It does NOT upload scratch source files.
- B differential patch oracle reads fresh-1/scratch after the native probes complete.

Run parser controls offline with: python3 -m unittest discover -s tests/etn -v

A passing regression is not an exploit. Distinct processes do not establish separately initialized application state, deployed default exposure, or security impact. For E3 each target fixture must separately create and attest fresh disposable chain/validator state and demonstrate the violated invariant; E4 requires production reachable attacker control and independent public reproduction.

CI budget: 3 x 1200 seconds maximum plus B patch check, within 75 minutes per class job. Cost can increase versus a single go test -count=3. Target code and prior evidence remain unchanged.
