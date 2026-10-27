from pqblocks_cbom import CBOMEnricher, CBOMProfile

enricher = CBOMEnricher(CBOMProfile.CNSA20)
sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [{"type": "library", "name": "liboqs", "version": "3.5.7"}]
}
cbom = enricher.enrich_sbom(sbom)
print("Enriched components:", len(cbom["components"]))
print("Injected properties:", [p["name"] for p in cbom["components"][0]["properties"]])
