# pqblocks-cbom

> High-throughput CycloneDX 1.5 CBOM metadata enrichment engine injecting quantum-safe classifications and CNSA 2.0 compliance properties.

[![CI](https://github.com/PQBlocks/cbom-enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/cbom-enricher/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-cbom` is an ultra-fast metadata enrichment engine and CLI that transforms standard **CycloneDX 1.5 Software Bill of Materials (SBOM)** documents into **Cryptographic Bill of Materials (CBOM)** enriched with post-quantum cryptography properties.

Designed for high-speed CI/CD pipelines, `pqblocks-cbom` operates purely on CPU using deterministic property injection and validation. It enriches 10,000 components in just 13 milliseconds with zero runtime dependencies.

### Standards Alignment

- **OWASP CycloneDX v1.5**: Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) specification.
- **NIST FIPS 203 / 204 / 205**: Module-Lattice and Hash-Based Post-Quantum Cryptography standards (ML-KEM, ML-DSA, SLH-DSA).
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite 2.0 requirements for national security systems.
- **CBOM Profiles**: Support for `cnsa20` and `ccf` (Cryptographic Concentration Framework) property sets.

> [!WARNING]
> **Non-FIPS Notice**: This library is an independent open-source metadata processor and policy tool. It is not evaluated under FIPS 140-3 and has not undergone CMVP validation. It records and verifies bill of materials metadata; it does not execute cryptographic key encapsulation or signature primitives.

---

## Installation

```bash
pip install pqblocks-cbom
```

### Dependencies

Requires Python 3.11+. The core engine and CLI require **zero third-party runtime dependencies** (`dependencies = []`).

---

## Quickstart

### Python API

```python
from pqblocks_cbom import CBOMEnricher, CBOMProfile

# Initialize enricher with NSA CNSA 2.0 profile
enricher = CBOMEnricher(CBOMProfile.CNSA20)

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {"type": "library", "name": "liboqs", "version": "3.5.7"}
    ]
}

cbom = enricher.enrich_sbom(sbom)
print("Enriched components:", len(cbom["components"]))
print("Injected properties:", [p["name"] for p in cbom["components"][0]["properties"]])
```

### CLI Interface

```bash
# Enrich an existing CycloneDX SBOM
pqblocks-cbom enrich sbom.json --profile cnsa20 -o cbom.json

# Validate a CBOM against profile rules
pqblocks-cbom validate cbom.json --profile cnsa20

# Scan a source tree and generate enriched CBOM
pqblocks-cbom scan ./src --profile cnsa20 -o cbom.json

# Generate a verifiable attestation manifest package
pqblocks-cbom attest cbom.json --profile cnsa20 -o ./attestation_output/
```

---

## Features

- **Extreme Performance**: Enriches 10,000 components in ~13 ms (>768,000 components/second). Single-component classification in 0.80 µs.
- **Zero Runtime Dependencies**: Written entirely in pure Python standard library (`json`, `hashlib`, `argparse`, `datetime`, `enum`).
- **Deterministic & Idempotent**: Re-enriching existing CBOMs does not duplicate properties or alter existing component metadata.
- **Automated Attestation**: Generates attestation manifests with SHA-256 digests and profile validation state.
- **Interoperable**: Fully tested and round-trip compatible with `cyclonedx-python-lib` 11+.

---

## Documentation

- [BENCHMARKS.md](BENCHMARKS.md) - Empirical throughput and scaling measurements.
- [TESTING.md](TESTING.md) - Test harness details and 95% statement coverage.
- [EVIDENCE.md](EVIDENCE.md) - Standard mappings and parameter table references.
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) - Multi-python verification log.
- [USE_CASES.md](USE_CASES.md) - Pipeline recipes and security compliance workflows.
- [SECURITY_NOTES.md](SECURITY_NOTES.md) - Security scope and defensive parser design.
- [AGENTS.md](AGENTS.md) - Automated verification and integration instructions.
- [CHANGELOG.md](CHANGELOG.md) - Release history.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
