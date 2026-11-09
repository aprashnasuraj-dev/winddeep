# [PRIVATE] Rapyd / Bugcrowd finding report template
**DO NOT COMMIT A COMPLETED VERSION TO PUBLIC GIT.** This is a blank structure only.

## Submission overview
- **Concise title:** [vulnerability class] in [approved asset/function] permits [observed unauthorized consequence]
- **Program:** Rapyd / Bugcrowd; engagement URL: https://bugcrowd.com/engagements/rapyd
- **Affected target:** [exact in-scope host/path, no third-party redirect]
- **Category / CWE / Bugcrowd VRT:** [classification and independently supported priority P0–P3]
- **Policy checked:** [authenticated official brief, timestamp, scope revision, relevant rules; store policy screenshot privately]
- **Researcher account/personas:** [self-owned masked identities and access role; NEVER store credentials]
- **Testing authorization:** [brief+participation+approved technique+safe-use boundaries]

## Executive impact
State what an attacker with [minimal prerequisites] can do that a normal user cannot. Distinguish funds-at-risk from actual transaction execution and prevent any real financial harm. If no unauthorized boundary violation was observed, status is CANDIDATE, not a vulnerability.

## Reproduction (non-destructive, exact)
1. Preconditions and owned fixtures; pinned application/build version and UTC time.
2. Positive experiment command/HTTP request *redacted* with only necessary headers/body.
3. Exact observed response, state transition and evidence hashes.
4. Honest NEGATIVE control with unchanged environment and one critical input difference.
5. Independent verification/oracle; explain alternative explanations.
6. Cleanup/reversal of owned state; no third-party data or irreversible financial effects.

## Security reasoning
- **Boundary crossed:** [attacker-controlled input → server authority decision → forbidden result]
- **Expected invariant:** [explicit]
- **Observed violation:** [explicit; quantification]
- **Strongest counterexample/defense:** [a concrete condition under which the finding does not hold]
- **Severity/VRT rationale:** [prerequisites, consistency, blast radius, demonstrated impact; avoid speculation]
- **Limitations and untested cases:** [all]

## Novelty and duplicate review
Link private previous objective fingerprints; prior submission references (if owned), known issues and materially distinct behavior. Do not present a theoretical variant of a known issue as newly found.

## Evidence chain
Provide SHA256 fingerprints of minimal `POC/`, `EVIDENCE/` and `EVIDENCE/CONTROL/`. Mark REAL_TARGET vs ISOLATED_FIXTURE. Record any environment blocker as NOT_EXECUTED. Full raw evidence is private; public summary is sanitized.

## Remediation (optional)
Explain the principle that restores the specific failed authorization or invariant. Do not substitute generic hardening for exploit proof.

## Delivery
`G0 G1 G2 G3 G4` statuses, `PACKAGE_VERIFIED`, `LIBRARY_VERIFIED`, `CHAT_DELIVERED`, submission acknowledgement ID (only if actually obtained). Human researcher reviews and submits on Bugcrowd.
