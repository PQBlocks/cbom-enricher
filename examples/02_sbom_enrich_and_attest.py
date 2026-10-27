"""Example 2: Complete SBOM Enrichment, Validation, and Attestation Pipeline.

Demonstrates reading an SBOM, enriching components with CNSA 2.0 and FIPS 203
post-quantum properties, validating compliance, and generating an attestation package.
"""

import os
import tempfile
from pqblocks_cbom import CBOMEnricher, CBOMProfile

def main():
    print("Initializing CBOMEnricher with CNSA 2.0 profile...")
    enricher = CBOMEnricher(CBOMProfile.CNSA20)

    # Simulated CycloneDX 1.5 SBOM containing mixed cryptographic libraries
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "liboqs",
                "version": "0.10.0",
                "description": "Open Quantum Safe cryptographic library"
            },
            {
                "type": "library",
                "name": "openssl",
                "version": "3.5.0",
                "description": "TLS toolkit with hybrid quantum support"
            },
            {
                "type": "library",
                "name": "cryptography",
                "version": "43.0.0",
                "description": "Python cryptographic recipes"
            }
        ]
    }

    # 1. Enrich SBOM
    enriched_cbom = enricher.enrich_sbom(sbom)
    print(f"Total components enriched: {len(enriched_cbom['components'])}")
    for comp in enriched_cbom["components"]:
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        print(f" - {comp['name']} ({comp['version']}):")
        print(f"     Family: {props.get('appliedquantum.algorithm.family')}")
        print(f"     Classification: {props.get('appliedquantum.algorithm.classification')}")
        print(f"     Standard: {props.get('appliedquantum.algorithm.std_reference')}")

    # 2. Validate Enriched CBOM
    validation = enricher.validate(enriched_cbom, CBOMProfile.CNSA20)
    print(f"Validation Status: valid={validation['valid']}, error_count={len(validation['errors'])}")

    # 3. Generate Attestation Package
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = enricher.attest(enriched_cbom, CBOMProfile.CNSA20, tmpdir)
        print(f"Attestation package generated at: {os.path.basename(manifest_path)}")
        assert os.path.exists(manifest_path), "Attestation manifest missing"
        assert os.path.exists(os.path.join(tmpdir, "cbom.json")), "cbom.json missing"

    print("Pipeline completed successfully.")

if __name__ == "__main__":
    main()
