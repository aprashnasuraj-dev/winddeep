# TransferWise GitHub audit status

- Branch: `transferwise`
- Current workflow commit: `aeeb1e6dd8a5b0d20634343eda44f2115c248598`
- Verified workflow run: `42574097183` — **SUCCESS**
- Scope: `github.com/transferwise/*`
- Explicit exclusion: `transferwise/pipelinewise`
- Public repositories inventoried after exclusion: **152**
- First prioritized audit batch: **30/30 completed successfully**
- Initial high-signal static candidates in that batch: **0**
- Automatically reportable findings: **0** by design; scanner/static output can never self-promote
- Outside-org repositories: blocked before checkout
- Third-party/upstream-only issues: non-rewardable unless Wise-specific behavior/impact is demonstrated
- Placeholder/sample secrets: suppressed
- Credential login validation: disabled in automation
- Known reported issues: **5** (fingerprints unavailable; manual dedupe remains required)
- Full inventory and per-repository source-review JSON are preserved as GitHub Actions artifacts

## Interpretation

The zero-candidate result applies only to the first detector layer (GitHub Actions privilege patterns, non-placeholder secret/key leads, shell=True, and unsafe YAML-load leads). It is **not** evidence that these repositories are vulnerability-free. Deeper manual/data-flow and repository-specific hypothesis work is still required.

## Verified first-batch repositories

`wise-topic`, `public-api-postman-collection`, `cloudflare-prometheus-exporter`, `banks-reference-android`, `public-widgets`, `neural-lifetimes`, `digital-signatures-examples`, `prometheus-envoy-dashboards`, `wise-platform-samples`, `idempotence4j`, `.github`, `actions-next-bundle-analyzer`, `legal-terms`, `pipelinewise-singer-python`, `shap-select`, `sequence-layout`, `grails-spring-security-oauth`, `tw-challenge-february-2015`, `onfido-api-java-client`, `aws-kms-sign-csr`, `wise-pizza`, `terraform-provider-awslambda`, `prometheus-anomaly-detector`, `plaid-java`, `vero-java`, `wait-for-it`, `ansible-cloudwatch-monitoring`, `admin_power_pack`, `ansible-docker`, `ansible-ebs-automatic-nvme-mapping`.
