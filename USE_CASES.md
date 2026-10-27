# Use Cases: pqblocks-cbom

## 1. Automated CI/CD Bill of Materials Enrichment

Integrate SBOM enrichment into GitHub Actions, GitLab CI, or Jenkins build workflows:

```bash
# Generate baseline SBOM using Syft or Trivy
syft dir:. -o cyclonedx-json=sbom.json

# Enrich SBOM with post-quantum compliance properties
pqblocks-cbom enrich sbom.json --profile cnsa20 -o cbom.json

# Enforce compliance gate
pqblocks-cbom validate cbom.json --profile cnsa20
```

## 2. Supply Chain Security Attestation

Produce tamper-evident attestation bundles for customers and compliance auditors:

```python
from pqblocks_cbom import CBOMEnricher, CBOMProfile

enricher = CBOMEnricher(CBOMProfile.CNSA20)
cbom = enricher.enrich_sbom(source_sbom)

# Generate attestation manifest with SHA-256 digests
enricher.attest(cbom, CBOMProfile.CNSA20, "./release-attestations/")
```

## 3. Cryptographic Inventory Scans

Scan local source repositories to identify quantum-vulnerable and post-quantum dependencies:

```bash
pqblocks-cbom scan ./backend-services --profile cnsa20 --json
```
