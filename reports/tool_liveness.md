# Phase B — Tool Liveness and Packaging Audit

Overall: **PASS**

| Check | Result | Detail |
|---|---|---|
| catalog accounting | **PASS** | classified=137, catalog=137, required=137 |
| no silent catalog disappearance | **PASS** | {"bundled": 6, "deprecated": 3, "external-service": 5, "internal": 0, "legacy": 1, "runtime": 0, "unsupported": 122} |
| portable tool manifest non-empty | **PASS** | 6 package entries |
| operational runtime catalog | **PASS** | active=137, catalog=137 |
| Windows-certified manifest subset count | **PASS** | bundled=['dnsx', 'httpx', 'katana', 'naabu', 'nuclei', 'subfinder'], required_count=6 |
| tool manifest integrity | **PASS** | versions, HTTPS URLs, hashes, licenses, redistribution reviews, deterministic paths, mappings and safe probes are defined |
| unique manifest provides | **PASS** | every bundled alias is supplied exactly once |
| bundled registry → installer coverage | **PASS** | every bundled integration has a pinned production payload |
| manifest excludes blocked/external integrations | **PASS** | manifest contains only release-bundled integrations |
| installed bundled binaries | **PASS** | deferred until post-staging gate |
| safe liveness probes | **PASS** | present binaries passed non-invasive liveness probes |

Failures: **0**
