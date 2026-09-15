# Windeep v3 target classes

Windeep v3 broadens what can be declared as an authorized target without broadening what can bypass preflight. Every declaration is an explicit scope object with its own consent token, justification, port set, and optional SNI/Host constraints.

## Supported classes

| Class | Meaning |
|---|---|
| `domain` | Exact DNS name |
| `subdomain` | Exact subdomain declaration |
| `ipv4` | Literal IPv4 address |
| `ipv6` | Literal IPv6 address; zone/scope IDs are refused |
| `cidr` | Explicit IPv4/IPv6 CIDR range |
| `ip_range` | Explicit inclusive `start-end` IP range |
| `url` | Absolute HTTP(S) URL |
| `ip_url` | Absolute HTTP(S) URL whose authority is a literal IP |
| `service` | Explicit host/IP + port service; IPv6 uses `[address]:port` |
| `contract` | Explicit 20-byte hexadecimal smart-contract address |
| `source_repo` | Explicit HTTP(S) source repository URL |

Every row in `v3_targets` carries the scan id, class, encrypted value, encrypted declared ports, encrypted SNI list, encrypted Host/`:authority` list, encrypted consent token id, encrypted justification, optional `max_hosts`, and creation time.

## Guardrail sequence

A declaration is accepted only after `PreFlightGuard.authorize_scan()` succeeds for the declared value and consent token. Before any IP HTTPS send, Windeep checks the selected port, SNI, and Host against that declaration, re-runs live preflight, and acquires per-IP and per-host rate capacity. The capture-layer connector performs an additional preflight immediately before the literal-IP socket when used directly.

An undeclared port, SNI, or Host is a denial event. The connector is not called and nothing is silently substituted.

## Literal-IP HTTPS

`ip_url` preserves the literal IP as the transport destination and replay destination. Windeep performs two observation-only TLS views when requested by the operator workflow:

1. **IP-SAN verification attempt.** A normal trust/hostname verification is attempted against the literal IP. Success is recorded as `verified_ip_san`; certificate validation failure is recorded as evidence and an unverified observation connection may be used only to capture the certificate/HTTP response from the same already-declared IP.
2. **SNI-less view.** The same declared IP is contacted without SNI. The leaf certificate IP SAN is inspected and the result is recorded separately, including `name_mismatch_observed` when applicable.

Certificate failure is evidence, not a reason to retarget. The capture records the peer/server IP, SNI sent, Host sent, TLS version/cipher, leaf fingerprint, best-available certificate chain, verification attempt, and verification outcome. On runtimes where the TLS implementation cannot expose intermediates, `cert_chain_complete=false` is recorded rather than fabricating a full chain.

The HAR schema remains frozen at `windeep.har-extension.v1`; v3 target fields are additive members of the existing `_winddeep` block. IP replay metadata pins the original literal IP so DNS cannot change the destination.

## CIDR and IP-range planning

CIDR/range expansion is deterministic for the same declaration and seed. `max_hosts` is mandatory and limits the number of hosts that can be attempted. The planner also acquires an aggregate range-rate token and a per-IP rate token for every selected host. Every candidate is audited as either `attempted` or `skipped`, with the skip reason.

### Auditable-range bound

C8 requires every attempted/skipped host to be auditable while P6 requires bounded memory, time, and artifact budgets. To satisfy both, one declaration may contain at most **4096 auditable candidate hosts**. A larger CIDR/range must be split into smaller explicitly consented declarations. This does not infer or silently shrink scope: the operator decides and records each split, and each split has its own consent/justification record.

## IPv6

IPv6 has the same declaration, port, rate, evidence, and replay rules as IPv4. Service syntax uses `[v6]:port`. Zone/scope identifiers such as `fe80::1%eth0` are refused because they are host-local routing hints, not portable authorization identities.

## PTR / reverse DNS

PTR results are stored as encrypted `recon.ptr` artifacts. They explicitly carry `expands_scope=false`. A hostname learned through reverse DNS does **not** become a target; testing it requires its own declared target and consent.

## Non-standard ports

Ports are never inferred from discovery. A non-standard port is eligible only when it appears in the declaration's explicit port set. For an `ip_url`, the URL authority port must also be present in that set.

## Operator checklist

Before starting an expanded target scan, verify that the exact IP/range/URL is in program scope, the consent token names that scope, the justification is meaningful, every port is explicit, every SNI/Host value is explicit, the CIDR/range has a safe `max_hosts`, and the scan budget/rate limits are appropriate. A PTR name or certificate name never expands any of those declarations automatically.
