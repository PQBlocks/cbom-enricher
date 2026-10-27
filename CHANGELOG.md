# Changelog: pqblocks-cbom

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- Initial public release of `pqblocks-cbom`.
- High-throughput SBOM metadata enrichment engine (`CBOMEnricher`).
- Support for `CNSA20` and `CCF` profiles.
- Automated component classification (`classify_component`) across ML-KEM, ML-DSA, SLH-DSA, and hybrid schemes.
- Attestation package generation with SHA-256 integrity digests.
- CLI interface (`pqblocks-cbom`) with `enrich`, `validate`, `scan`, and `attest` subcommands.
- Comprehensive test harness with 56 unit/KAT tests and 95% statement coverage.
