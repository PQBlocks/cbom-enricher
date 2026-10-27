# Verification Report: pqblocks-cbom

This report documents the verification results across supported Python runtimes.

## Verification Matrix

- **Package**: `pqblocks-cbom`
- **Version**: 0.1.0
- **Test Suite**: 56 automated tests
- **Coverage**: 95% statement coverage (308/323 statements)

| Python Version | Wheel Build | Test Suite | Examples Execution | Gate Status |
|---|---|---|---|---|
| Python 3.11 | PASS | 56 passed | 2 examples passed | **PASS** |
| Python 3.12 | PASS | 56 passed | 2 examples passed | **PASS** |
| Python 3.13 | PASS | 56 passed | 2 examples passed | **PASS** |
| Python 3.14 | PASS | 56 passed | 2 examples passed | **PASS** |

## Executed Examples

1. `examples/quickstart.py`: Validates basic CycloneDX SBOM enrichment and property extraction.
2. `examples/02_sbom_enrich_and_attest.py`: Validates complete pipeline: multi-component enrichment, CNSA 2.0 validation, and manifest generation.

## Zero Leaks Verification

Scanned repository files against internal patterns and markers. Result: **0 leak hits**.
