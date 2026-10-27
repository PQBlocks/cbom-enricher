# Agents Guide: pqblocks-cbom

This document provides machine-readable instructions for automated agents maintaining `pqblocks-cbom`.

## Validation Commands

```bash
# Run test suite
pytest -v

# Check coverage
pytest --cov=pqblocks_cbom --cov-fail-under=90

# Run examples
python examples/quickstart.py
python examples/02_sbom_enrich_and_attest.py
```

## Public API Symbols

Exports from `pqblocks_cbom`:
- `CBOMEnricher`
- `CBOMProfile`
- `classify_component`
- `canonicalize_property`

## Architecture Rules

- Maintain zero external runtime dependencies (`dependencies = []`).
- Preserve compatibility with CycloneDX 1.5 JSON schemas.
- Ensure all property names remain under standard namespaces.
