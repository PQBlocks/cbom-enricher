# Security Notes: pqblocks-cbom

## Operational Scope

`pqblocks-cbom` is a metadata processing and static policy enforcement engine.

- **No Cryptographic Execution**: This package does not implement cryptographic algorithms (e.g., lattice math or key generation). It records and validates metadata describing cryptographic implementations.
- **Integrity Verification**: The attestation generator computes SHA-256 digests over enriched files. These digests should be paired with signature mechanisms (such as Sigstore or X.509 code signing) for supply chain security.

## Defensive Design

1. **Deterministic Processing**: Input components are enriched in-place or copied cleanly without executing external code.
2. **Path Traversal Protection**: File inputs and outputs are resolved safely without invoking shell interpreters.
3. **No Unsafe Deserialization**: All parsing uses standard library `json.loads` without reflection.

## Disclaimers

> [!NOTE]
> `pqblocks-cbom` is not evaluated under NIST FIPS 140-3 or CMVP. It serves as an open-source auditing and metadata enrichment utility.
