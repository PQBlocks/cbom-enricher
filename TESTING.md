# Testing: pqblocks-cbom

## Test Suite Overview

`pqblocks-cbom` contains an automated test suite comprising 56 unit and known-answer tests (KATs).

### Test Execution

Run the suite using pytest:

```bash
pytest -v
```

With coverage measurement:

```bash
pytest --cov=pqblocks_cbom --cov-report=term-missing
```

## Coverage Report

The test suite achieves **95% statement coverage** across all source files:

| Module | Statements | Missing | Coverage |
|---|---|---|---|
| `pqblocks_cbom/__init__.py` | 4 | 0 | **100%** |
| `pqblocks_cbom/__main__.py` | 78 | 5 | **94%** |
| `pqblocks_cbom/classify.py` | 65 | 0 | **100%** |
| `pqblocks_cbom/enricher.py` | 176 | 10 | **94%** |
| **Total** | **323** | **15** | **95%** |

## Test Scenarios Covered

1. **CycloneDX 1.5 Interoperability**:
   - Serialization and deserialization round-trip using `cyclonedx-python-lib`.
   - Property preservation across multi-component BOMs.
2. **Known Answer Testing (KATs)**:
   - FIPS 203 / 204 / 205 parameter set tables verified against authoritative standards.
   - Component classification KATs covering liboqs, OpenSSL, pyca/cryptography, Botan, and Bouncy Castle.
3. **Idempotency & Non-Duplication**:
   - Enriched SBOM passed through multiple enrichment rounds without property duplication.
4. **CLI Subcommands**:
   - `enrich`, `validate`, `scan`, `attest` executed via subprocess and direct programmatic invocations.
   - Exit code verification and error handling for missing files.
5. **Attestation Generation**:
   - SHA-256 digest calculation for generated `cbom.json` and verification of manifest structure.
