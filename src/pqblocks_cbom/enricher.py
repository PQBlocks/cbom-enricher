"""CBOM Enricher - Core enrichment logic for PQ metadata."""

from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

import json
import hashlib
from datetime import datetime, timezone


class CBOMProfile(Enum):
    """CBOM Profile selection for validation and property set."""
    CNSA20 = "cnsa20"
    CCF = "ccf"


class CBOMEnricher:
    """Enriches CycloneDX SBOMs with post-quantum metadata."""

    def __init__(self, profile: CBOMProfile = CBOMProfile.CNSA20) -> None:
        if not isinstance(profile, CBOMProfile):
            accepted = ", ".join(p.value for p in CBOMProfile)
            raise ValueError(
                "Unknown profile: %r. Accepted profiles are: %s "
                "(pass a CBOMProfile enum member, not None or a string)"
                % (profile, accepted)
            )
        self.profile = profile
        self._tier1_properties = self._get_tier1_properties()

    def _get_tier1_properties(self) -> List[str]:
        """Get Tier 1 mandatory properties per CBOM Profile."""
        if self.profile == CBOMProfile.CNSA20:
            return [
                'appliedquantum.algorithm.family',
                'appliedquantum.algorithm.classification',
                'appliedquantum.algorithm.key_size',
                'appliedquantum.algorithm.std_reference',
            ]
        elif self.profile == CBOMProfile.CCF:
            return [
                'appliedquantum.algorithm.family',
                'appliedquantum.algorithm.classification',
                'appliedquantum.algorithm.key_size',
                'appliedquantum.algorithm.vendor_id',
                'appliedquantum.algorithm.std_reference',
            ]
        return []

    def enrich_sbom(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a CycloneDX 1.5 SBOM dict with PQ metadata.

        Idempotent: re-enriching an already-enriched SBOM adds no property that
        the component already carries (same name), so a second call returns an
        identical structure. Values of pre-existing appliedquantum.* properties
        are preserved, not overwritten.
        """
        if not isinstance(sbom, dict):
            raise ValueError("Invalid SBOM: not a dictionary")
        if 'components' not in sbom:
            raise ValueError("Missing 'components' field in SBOM")

        enriched = dict(sbom)
        enriched_components = []

        for comp_data in sbom.get('components', []):
            if not isinstance(comp_data, dict):
                raise ValueError("Invalid component: not a dictionary")
            name = comp_data.get('name')
            if not name:
                raise ValueError("Missing 'name' field in component")

            existing_props = comp_data.get('properties', [])
            imports = self._extract_imports(comp_data)
            classification = self._classify_component(name, comp_data.get('version', ''), imports)

            enriched_comp = dict(comp_data)
            enriched_props = list(existing_props)
            existing_names = {p.get('name') for p in existing_props if isinstance(p, dict)}

            if classification.get('family') != 'UNKNOWN':
                for prop_name in ['family', 'classification', 'key_size', 'std_reference']:
                    if prop_name in classification and classification[prop_name]:
                        full_prop = f'appliedquantum.algorithm.{prop_name}'
                        if full_prop not in existing_names:
                            enriched_props.append({'name': full_prop,
                                                   'value': str(classification[prop_name])})
                            existing_names.add(full_prop)

            if self.profile == CBOMProfile.CCF and classification.get('vendor_id'):
                full_prop = 'appliedquantum.algorithm.vendor_id'
                if full_prop not in existing_names:
                    enriched_props.append({'name': full_prop,
                                           'value': str(classification['vendor_id'])})
                    existing_names.add(full_prop)

            enriched_comp['properties'] = enriched_props
            enriched_components.append(enriched_comp)

        enriched['components'] = enriched_components
        return enriched

    def _extract_imports(self, comp_data: Dict[str, Any]) -> List[str]:
        imports = []
        for ext_ref in comp_data.get('externalReferences', []):
            if ext_ref.get('type') == 'distribution':
                url = ext_ref.get('url', '')
                if 'liboqs' in url or 'oqs' in url:
                    imports.append('liboqs')
                if 'openssl' in url.lower():
                    imports.append('openssl')
                if 'cryptography' in url.lower():
                    imports.append('cryptography')
        purl = comp_data.get('purl', '')
        if 'liboqs' in purl:
            imports.append('liboqs')
        if 'openssl' in purl:
            imports.append('openssl')
        if 'cryptography' in purl:
            imports.append('cryptography')
        return imports

    def _classify_component(self, name: str, version: str, imports: List[str]) -> Dict[str, str]:
        """Classify component based on name/version/imports."""
        name_lower = name.lower()
        classification = {
            'family': 'UNKNOWN',
            'classification': 'UNKNOWN',
            'key_size': '',
            'std_reference': '',
            'vendor_id': ''
        }

        # liboqs detection
        if any('liboqs' in imp for imp in imports) or 'liboqs' in name_lower or 'oqs' in name_lower:
            classification['family'] = 'ML-KEM'
            classification['classification'] = 'SAFE'
            classification['key_size'] = '768'
            classification['std_reference'] = 'FIPS 203'
            classification['vendor_id'] = 'IAOE'
            return classification

        # OpenSSL 3.5 detection
        if 'openssl' in name_lower:
            classification['family'] = 'X25519Kyber768'
            classification['classification'] = 'TRANSITIONAL'
            classification['key_size'] = '768'
            classification['std_reference'] = 'FIPS 203'
            classification['vendor_id'] = 'OSSL'
            return classification

        # pyca cryptography
        if 'cryptography' in name_lower:
            classification['family'] = 'ML-DSA'
            classification['classification'] = 'SAFE'
            classification['key_size'] = '65'
            classification['std_reference'] = 'FIPS 204'
            classification['vendor_id'] = 'PyCA'
            return classification

        return classification

    def scan_path(self, path: str, output_format: str = "cyclonedx-json") -> Dict[str, Any]:
        import os
        if not os.path.exists(path):
            raise ValueError(f"Path does not exist: {path}")
        if output_format != "cyclonedx-json":
            raise ValueError(f"Unsupported output format: {output_format}")

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }

        components = self._scan_for_pqc_components(path)
        sbom["components"] = components
        return self.enrich_sbom(sbom)

    def _scan_for_pqc_components(self, path: str) -> List[Dict[str, Any]]:
        import os
        components = []

        for root, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                if 'liboqs' in filepath.lower() or 'oqs' in filepath.lower():
                    components.append({
                        "type": "library",
                        "name": "liboqs",
                        "version": "3.5.7",
                        "purl": "pkg:generic/liboqs@3.5.7",
                        "externalReferences": [
                            {"type": "distribution", "url": "https://github.com/open-quantum-safe/liboqs"}
                        ]
                    })
                elif 'openssl' in filepath.lower() and ('3.5' in filepath or '3_5' in filepath):
                    components.append({
                        "type": "library",
                        "name": "OpenSSL",
                        "version": "3.5.0",
                        "purl": "pkg:generic/openssl@3.5.0",
                        "externalReferences": [
                            {"type": "distribution", "url": "https://github.com/openssl/openssl"}
                        ]
                    })
                elif 'cryptography' in filepath.lower() and file.endswith('.py'):
                    components.append({
                        "type": "library",
                        "name": "cryptography",
                        "version": "42.0.0",
                        "purl": "pkg:pypi/cryptography@42.0.0",
                        "externalReferences": [
                            {"type": "distribution", "url": "https://github.com/pyca/cryptography"}
                        ]
                    })

        seen = set()
        unique = []
        for comp in components:
            key = (comp['name'], comp['version'])
            if key not in seen:
                seen.add(key)
                unique.append(comp)
        return unique

    def validate(self, cbom: Dict[str, Any], profile: Optional[CBOMProfile] = None) -> Dict[str, Any]:
        if profile is None:
            profile = self.profile

        errors = []
        components_total = 0
        components_with_pq_properties = 0
        components_unclassified = 0
        unsupported = []
        skipped = []

        if not isinstance(cbom, dict):
            return {
                "valid": False,
                "errors": ["CBOM is not a dictionary"],
                "components_total": 0,
                "components_with_pq_properties": 0,
                "components_unclassified": 0,
                "unsupported": [],
                "skipped": []
            }

        components = cbom.get('components', [])
        components_total = len(components)

        for comp in components:
            if not isinstance(comp, dict):
                continue
            name = comp.get('name', 'unknown')
            props = comp.get('properties', [])
            pq_props = [p for p in props if p.get('name', '').startswith('appliedquantum.')]
            if pq_props:
                components_with_pq_properties += 1
                tier1 = self._get_tier1_properties() if profile == self.profile else []
                if profile == CBOMProfile.CCF:
                    tier1 = [
                        'appliedquantum.algorithm.family',
                        'appliedquantum.algorithm.classification',
                        'appliedquantum.algorithm.key_size',
                        'appliedquantum.algorithm.vendor_id',
                        'appliedquantum.algorithm.std_reference',
                    ]
                for req in tier1:
                    if not any(p.get('name') == req for p in pq_props):
                        errors.append(f"Component '{name}': missing required property '{req}'")
            else:
                components_unclassified += 1
                unsupported.append(f"{name}: no appliedquantum properties found")

        valid = len(errors) == 0
        return {
            "valid": valid,
            "errors": errors,
            "components_total": components_total,
            "components_with_pq_properties": components_with_pq_properties,
            "components_unclassified": components_unclassified,
            "unsupported": unsupported,
            "skipped": skipped
        }

    def attest(self, cbom: Dict[str, Any], profile: CBOMProfile, output_dir: str) -> str:
        import os
        os.makedirs(output_dir, exist_ok=True)
        validation = self.validate(cbom, profile)

        cbom_path = os.path.join(output_dir, "cbom.json")
        with open(cbom_path, 'w') as f:
            json.dump(cbom, f, indent=2)

        manifest = {
            "profile": profile.value,
            "tool_version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "validation": {
                "valid": validation["valid"],
                "errors": validation["errors"]
            },
            "files": []
        }

        with open(cbom_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        manifest["files"].append({
            "path": "cbom.json",
            "sha256": sha256
        })

        manifest_path = os.path.join(output_dir, "manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        return manifest_path
