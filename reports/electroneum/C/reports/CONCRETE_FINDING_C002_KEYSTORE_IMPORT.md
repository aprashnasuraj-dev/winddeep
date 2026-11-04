# C-002 — Malformed Encrypted Keystore JSON Panics Through Exported KeyStore.Import

**Classification:** CONFIRMED Electroneum software defect at the exported encrypted-keystore import boundary. **Concrete demonstrated impact:** malformed local/library-supplied encrypted key JSON can trigger Go panics instead of returning an error. **Not demonstrated:** default remote RPC exploit, private-key theft, unauthorized signing, ETN transfer, chain/finality impact, or a shipped CLI path that imports arbitrary encrypted JSON.

### 1. Vulnerability Detail with Proof of /electroneum-sc Git Codes/Sources

**Certified target identity**
- Windeep source commit: `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`
- Git tree: `de7f3c75a2db7e87a89918f1257820703d5b731e`
- Pinned upstream: `3aeb14db0d6384243302f3a025bdff904dc28bf6`
- Historical archive provenance SHA-256: `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`

**Exported trust boundary**
- [`accounts/keystore/keystore.go:437–453`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/accounts/keystore/keystore.go#L437-L453) exposes `func (ks *KeyStore) Import(keyJSON []byte,...)`. It calls `DecryptKey` directly and contains no panic recovery.
- [`accounts/keystore/passphrase.go:200–227`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/accounts/keystore/passphrase.go#L200-L227) parses V3 JSON and delegates to `decryptKeyV3`.
- [`accounts/keystore/passphrase.go:240–273`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/accounts/keystore/passphrase.go#L240-L273) decodes IV/ciphertext, derives a key, slices `derivedKey[16:32]`, and calls AES-CTR.
- [`accounts/keystore/passphrase.go:330–367`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/accounts/keystore/passphrase.go#L330-L367) contains unchecked dynamic-JSON assertions: `KDFParams["salt"].(string)`, PBKDF2 `["prf"].(string)`, and `ensureInt` falls through to `x.(float64)`.

**Concrete root causes reproduced**
1. Missing KDF `salt` → unchecked nil-to-string type assertion panic.
2. Numeric KDF `salt` → float64-to-string type assertion panic.
3. Invalid AES-CTR IV length → cipher initialization panic (`bad IV length`).
4. In contrast, unsupported cipher and invalid MAC hex return ordinary errors. These controls show the harness is not labeling every malformed file as a panic.

**Exposure controls / counterexample**
- [`node/defaults.go:52–64`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/node/defaults.go#L52-L64) defaults HTTP/WS modules to `net` and `web3`, not `personal`.
- [`internal/ethapi/api.go:386–399`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L386-L399) `PrivateAccountAPI.ImportRawKey` accepts a hex private key and calls `ImportECDSA`, not encrypted JSON `KeyStore.Import`.
- [`cmd/etn-sc/accountcmd.go:341–358`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/cmd/etn-sc/accountcmd.go#L341-L358) `account import` loads an **unencrypted** ECDSA key and calls `ImportECDSA`; [lines 319–338](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/cmd/etn-sc/accountcmd.go#L319-L338) `wallet import` uses the separate presale importer.
- Therefore the defect is concrete in the exported library API and any embedding application that accepts encrypted JSON, but a default network-reachable import route was not found.

### 2. Possible Impact

**Demonstrated impact:** an application calling exported `KeyStore.Import` on malformed encrypted JSON receives a Go panic instead of a normal error for at least three independently varied inputs. If the application/request boundary does not recover the panic, the caller goroutine/process can terminate according to its panic policy, causing local wallet/import-service availability loss.

**Prerequisites:** an attacker or untrusted source must cause malformed encrypted-keystore JSON to be passed to `KeyStore.Import` (or another caller reaching the same decoder). This can occur in an embedding wallet/import service, file-upload workflow, plugin, or locally supplied file if such an integration exists.

**Not proven:** the standard Electroneum node configuration does not expose this encrypted-import API over default HTTP/WS RPC in the inspected source. No evidence demonstrates remote unauthenticated crash, theft of an existing private key, signing bypass, or blockchain safety impact.

**Severity mechanism:** denial of service / uncontrolled exception at a secret-management input boundary. Severity is deployment-dependent: local/manual import is low exposure; a network service wrapping `KeyStore.Import` without validation/recovery raises exposure substantially.

### 3. Proof of Concept

**R-only certified fixture:** [`reports/electroneum/C/reports/fixtures/reverse_c_import_boundary_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reports/fixtures/reverse_c_import_boundary_test.go). It generates a synthetic key locally, encrypts it using Electroneum's own `EncryptKey`, mutates only JSON fields, and calls the **actual exported** `KeyStore.Import`. No real keys, public nodes, network traffic, or live accounts are used.

**Certified runtime:** [GitHub Actions run 41747296488](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41747296488), job `126303401377`, **COMPLETED/SUCCESS**. The workflow first verifies the immutable source certificate, then copies it to a disposable scratch tree.

Executed:
```bash
go test -count=1 -timeout=10m -run '^TestReverseCExportedKeyStoreImportMatrix$' -v ./accounts/keystore
```
Exit **0** because the characterization test intentionally catches and classifies panics. Decisive outputs:
- `REVERSE_C_VALID_KEYSTORE_IMPORT_PASS`
- `REVERSE_C_EXPORTED_IMPORT_PANIC_OBSERVED case=missing_salt type=*runtime.TypeAssertionError value=interface conversion: interface {} is nil, not string`
- `REVERSE_C_EXPORTED_IMPORT_PANIC_OBSERVED case=numeric_salt type=*runtime.TypeAssertionError value=interface conversion: interface {} is float64, not string`
- `REVERSE_C_EXPORTED_IMPORT_PANIC_OBSERVED case=invalid_aes_ctr_iv type=string value=bad IV length`
- `REVERSE_C_EXPORTED_IMPORT_CONTROLLED_ERROR case=unsupported_cipher err=cipher not supported: not-a-supported-cipher`
- `REVERSE_C_EXPORTED_IMPORT_CONTROLLED_ERROR case=invalid_mac_hex ...`

**Independent fail-closed oracle:** the same run executed:
```bash
go test -count=1 -timeout=10m -run '^TestReverseCExportedImportFailClosedOracle$' -v ./accounts/keystore
```
The original certified source returned **exit 1 as expected**, with exact marker:
`REVERSE_C_EXPORT_IMPORT_FAIL_CLOSED_ORACLE_MISMATCH: missing salt panicked ...`

The workflow accepted that failure **only** if the named assertion marker appeared, preventing compilation/runner failures from being misclassified as target defects.

**Sensitivity proof:** R applied a salt-validation guard only to disposable scratch `accounts/keystore/passphrase.go`. The strict oracle then passed with:
`REVERSE_C_EXPORT_IMPORT_FAIL_CLOSED_ORACLE_PASS err=missing or invalid KDF salt`.
A SHA-256 check confirmed the certified source file remained unchanged. The defensive mutation is evidence that the oracle is causally sensitive to the defect, not a production patch.

**Process-level propagation confirmed:** R fixture commit `8992bb8b8a366087c889958acad6826a157a95ba` adds an unrecovered `KeyStore.Import` call. The first integration attempt [41747798427](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41747798427) had malformed YAML and zero jobs and is **not evidence**. After workflow repair `38ea75088822606739b54e1f9551930fde02c137`, [run 41747899973](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41747899973), job `126305410395`, completed **SUCCESS** because the wrapper required the child Go test to fail with the exact expected panic signature. The unrecovered command `go test -count=1 -timeout=10m -run TestReverseCExportedImportUnrecoveredPanic -v ./accounts/keystore` exited **1**. Logs contain `REVERSE_C_UNRECOVERED_IMPORT_BEGIN`, `panic: interface conversion: interface {} is nil, not string`, and a stack frame at `github.com/electroneum/electroneum-sc/accounts/keystore.(*KeyStore).Import`; the wrapper emitted `REVERSE_R_C_UNRECOVERED_IMPORT_PROCESS_FAILURE_CONFIRMED exit=1`. This concretely proves that without a recovery boundary the exported import panic propagates to Go process/test failure. It still does **not** prove that the default Electroneum node exposes attacker-controlled encrypted JSON remotely.

### 4. Recommendation

1. Replace direct KDF map type assertions with explicit typed extraction helpers. Missing, null, numeric, boolean, object, and string-invalid values must return structured errors.
2. Replace `ensureInt` with checked integer parsing: reject non-finite floats, fractional values, negatives where invalid, overflow, and absent values. Enforce safe resource bounds for scrypt/PBKDF2 work factors before allocation.
3. Validate `dklen` before slicing derived material; require the minimum bytes actually needed by the V3 format. Check `len(derivedKey)`, never rely on backing-array capacity.
4. Validate AES-CTR IV length equals `aes.BlockSize` before calling cipher construction. Return an error rather than allowing a panic from the crypto library.
5. Add regression tests through **exported `KeyStore.Import`**, not only `DecryptDataV3`: valid control, missing/wrong-type salt, missing/wrong-type numeric KDF parameters, PBKDF2 PRF, IV lengths, `dklen` boundaries, wrong password, invalid cipher/MAC and oversized KDF work factors.
6. Embedding services that expose encrypted-key import should apply authorization, request-size/KDF limits, and request-boundary panic recovery as defense in depth. Recovery does not replace input validation.
7. Keep default RPC exposure conservative. Do not expose a general encrypted-keystore import method to untrusted networks without an authenticated design and explicit file-validation boundary.

**Finding gate:** The exported API defect and deterministic panic are confirmed. Classification as a remotely exploitable Electroneum-node vulnerability remains **not established** until a shipped lower-trust caller can be shown to supply the malformed JSON and concrete availability/security impact is reproduced.
