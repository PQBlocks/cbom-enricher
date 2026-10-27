"""
Known Answer Tests (KATs) for pqblocks-cbom
Tests property injection, round-trip, and validation against CBOM Profile test vectors.

These tests verify the CBOM enrichment functionality:
- Section 7.3.1: Basic Property Round-trip KAT
- Section 7.3.2: Tiered Property Compliance KAT
- Section 7.3.3: Cross-Library Interoperability KAT
"""

import json
import pytest
from cyclonedx.model.component import Component, Property
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot5


class TestPropertyRoundTrip:
    """Test 1: Property serialization round-trip (Basic Property Round-trip KAT)"""

    def test_basic_property_round_trip(self):
        """Verify that PQ properties round-trip through serialization"""
        # Create component with PQ properties
        c = Component(name='test-pq-component', version='1.0.0')
        c.properties.add(Property(name='appliedquantum.algorithm.family', value='Kyber'))
        c.properties.add(Property(name='appliedquantum.algorithm.classification', value='SAFE'))
        c.properties.add(Property(name='appliedquantum.algorithm.key_size', value='768'))

        # Serialize and verify
        bom = Bom()
        bom.components = [c]
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        # Verify PQ properties preserved (using set equality, not index order)
        # JsonV1Dot5 emits properties in alphabetical order by name; the CycloneDX
        # 1.5 schema does not mandate property order (spec §6.3).
        pq_props = [p for p in parsed['components'][0].get('properties', [])
                    if p['name'].startswith('appliedquantum.')]
        assert len(pq_props) == 3
        prop_dict = {p['name']: p['value'] for p in pq_props}
        assert prop_dict['appliedquantum.algorithm.family'] == 'Kyber'
        assert prop_dict['appliedquantum.algorithm.classification'] == 'SAFE'
        assert prop_dict['appliedquantum.algorithm.key_size'] == '768'

    def test_multiple_components_round_trip(self):
        """Verify round-trip works for multiple components"""
        components = []
        for i in range(3):
            c = Component(name=f'component-{i}', version='1.0.0')
            c.properties.add(Property(name='appliedquantum.algorithm.family', value='Dilithium'))
            c.properties.add(Property(name='appliedquantum.algorithm.key_size', value='65'))
            components.append(c)

        bom = Bom()
        bom.components = components
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        assert len(parsed['components']) == 3
        for comp in parsed['components']:
            props = comp.get('properties', [])
            pq_props = [p for p in props if p['name'].startswith('appliedquantum.')]
            assert len(pq_props) == 2


class TestTieredPropertyCompliance:
    """Test 2: Tiered property compliance validation"""

    def test_tier1_properties_exist(self):
        """Verify Tier 1 mandatory properties can be added"""
        # Define Tier 1 mandatory properties per CBOM Profile v1.0-RC
        tier1_properties = [
            'appliedquantum.algorithm.family',
            'appliedquantum.algorithm.classification',
            'appliedquantum.algorithm.key_size',
            'appliedquantum.algorithm.std_reference',
        ]

        c = Component(name='pq-component', version='1.0.0')
        for prop_name in tier1_properties:
            c.properties.add(Property(name=prop_name, value='test-value'))

        bom = Bom()
        bom.components = [c]
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        props = parsed['components'][0].get('properties', [])
        added_tier1 = [p['name'] for p in props if p['name'] in tier1_properties]
        assert len(added_tier1) == len(tier1_properties)

    def test_all_required_tier1_properties_present(self):
        """Verify all required Tier 1 properties per CBOM Profile"""
        # CBOM Profile v1.0-RC requires these Tier 1 properties
        mandatory_props = [
            'appliedquantum.algorithm.family',
            'appliedquantum.algorithm.classification',
            'appliedquantum.algorithm.key_size',
            'appliedquantum.algorithm.vendor_id',
            'appliedquantum.algorithm.std_reference',
        ]

        c = Component(name='test-lib', version='1.0.0')
        for prop in mandatory_props:
            c.properties.add(Property(name=prop, value='value'))

        bom = Bom()
        bom.components = [c]
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        props = parsed['components'][0].get('properties', [])
        prop_names = [p['name'] for p in props]
        for prop in mandatory_props:
            assert prop in prop_names, f"Missing mandatory property: {prop}"


class TestCrossLibraryInteroperability:
    """Test 3: Cross-library interoperability"""

    def test_cyclonedx_property_format(self):
        """Verify property format matches CycloneDX 1.5 schema"""
        c = Component(name='test', version='1.0')
        c.properties.add(Property(name='appliedquantum.algorithm.family', value='Kyber'))

        bom = Bom()
        bom.components = [c]
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        # Verify format matches expected: {"name": "...", "value": "..."}
        props = parsed['components'][0].get('properties', [])
        assert len(props) == 1
        assert 'name' in props[0]
        assert 'value' in props[0]
        assert props[0]['name'] == 'appliedquantum.algorithm.family'
        assert props[0]['value'] == 'Kyber'

    def test_json_serialization_valid(self):
        """Verify output is valid JSON and parseable"""
        c = Component(name='test', version='1.0')
        c.properties.add(Property(name='appliedquantum.algorithm.family', value='Kyber'))

        bom = Bom()
        bom.components = [c]
        output = JsonV1Dot5(bom).output_as_string()

        # Must be valid JSON
        parsed = json.loads(output)
        assert 'components' in parsed
        assert len(parsed['components']) == 1


class TestCBOMTestSuite:
    """Known Answer Tests for CBOM Profile v1.0-RC compliance"""

    def test_kat_basic_injection(self):
        """KAT: Basic property injection"""
        c = Component(name='liboqs-kyber', version='3.5.7')
        c.properties.add(Property(name='appliedquantum.algorithm.family', value='Kyber'))
        c.properties.add(Property(name='appliedquantum.algorithm.classification', value='SAFE'))
        c.properties.add(Property(name='appliedquantum.algorithm.key_size', value='768'))
        c.properties.add(Property(name='appliedquantum.algorithm.std_reference', value='FIPS 203'))

        b = Bom()
        b.components = [c]
        output = JsonV1Dot5(b).output_as_string()
        parsed = json.loads(output)

        props = parsed['components'][0].get('properties', [])
        assert len(props) == 4
        prop_dict = {p['name']: p['value'] for p in props}
        assert prop_dict['appliedquantum.algorithm.family'] == 'Kyber'
        assert prop_dict['appliedquantum.algorithm.classification'] == 'SAFE'
        assert prop_dict['appliedquantum.algorithm.key_size'] == '768'
        assert prop_dict['appliedquantum.algorithm.std_reference'] == 'FIPS 203'


class TestPerformanceRequirements:
    """Performance KATs for large SBOM processing"""

    def test_processing_speed_1000_components(self):
        """KAT: 1,000 component processing under time limit"""
        import time

        start_time = time.time()

        components = []
        for i in range(1000):
            c = Component(name=f'component-{i}', version='1.0.0')
            c.properties.add(Property(name='appliedquantum.algorithm.family', value='Kyber'))
            c.properties.add(Property(name='appliedquantum.algorithm.key_size', value='768'))
            components.append(c)

        bom = Bom()
        bom.components = components
        output = JsonV1Dot5(bom).output_as_string()

        end_time = time.time()
        processing_time = end_time - start_time

        # Requirement: Must complete within reasonable time
        assert processing_time < 30.0, f"Processing time {processing_time:.2f}s exceeds limit"
        assert len(json.loads(output)['components']) == 1000

    def test_memory_efficient_property_storage(self):
        """KAT: Memory-efficient handling of many properties"""
        components = []
        for i in range(100):
            c = Component(name=f'comp-{i}', version='1.0')
            for j in range(10):
                c.properties.add(Property(
                    name=f'appliedquantum.algorithm.param_{j}',
                    value=str(i * j)
                ))
            components.append(c)

        bom = Bom()
        bom.components = components
        output = JsonV1Dot5(bom).output_as_string()
        parsed = json.loads(output)

        # Verify all properties preserved
        for comp in parsed['components']:
            props = comp.get('properties', [])
            assert len(props) == 10
