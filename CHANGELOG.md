# Changelog

All notable changes to Windeep are documented here. This project follows Semantic Versioning.

## [Unreleased]

### Added
- Repository bootstrap, Windows CI/release pipeline, issue templates, security policy, and contribution guide.
- Event-driven engine primitives: async event bus, DAG scheduler, dynamic tool wrapper factory, and scan context.
- Fail-closed release audits for module completeness, registry/installer coverage, dependency health, local guardrails, coverage, tag/version consistency, and clean Windows packaging.
- Clean Windows installer/portable audit covering embedded Python, Playwright browser payload, manifest-declared tool probes, loopback binding, version identity, and silent uninstall.
- Deterministic portable-tool staging with pinned HTTPS assets, SHA-256 verification, archive-member extraction, path-safety checks, licensing metadata, and non-invasive liveness probes.
- CycloneDX SBOM generation plus GitHub build-provenance/SBOM attestations for release artifacts.

### Changed
- Refreshed release workflow action majors while preserving the G1-G21 tag-release sequence.
- Release tooling now rejects an empty tool manifest instead of silently producing an incomplete installer.

## [0.1.0] - 2026-09-15

### Added
- Initial public project scaffold based on the Windeep master blueprint.
