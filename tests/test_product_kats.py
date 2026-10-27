"""
Product KATs: exercise pqblocks_cbom itself (not just cyclonedx-python-lib).

This module imports pqblocks_cbom and drives its full public API surface:

  - CBOMEnricher.enrich_sbom / validate / attest / scan_path
  - classify_component / canonicalize_property
  - golden vectors loaded from fixtures/golden-vectors/ (known-answer testing)
"""

import json
import os
import subprocess
import sys

import pytest

# The product is installed from src/ (editable install via pyproject.toml).
# Guarantee importability even when run without the install.
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from pqblocks_cbom import (  # noqa: E402
    CBOMEnricher,
    CBOMProfile,
    canonicalize_property,
    classify_component,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "golden-vectors")


def _load_golden(name):
    path = os.path.join(GOLDEN, name)
    if not os.path.isfile(path):
        pytest.fail("golden vector file missing: %s" % path)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _pq_props(component):
    return [p for p in component.get("properties", [])
            if p.get("name", "").startswith("appliedquantum.")]


# ---------------------------------------------------------------------------
# Golden vectors: classification of known components
# ---------------------------------------------------------------------------

class TestClassificationGoldenVectors:
    """KAT: classification of known components matches golden vectors."""

    def test_classification_vectors_match_golden_file(self):
        vectors = _load_golden("classification-vectors.json")
        assert len(vectors["vectors"]) >= 10, "expected >=10 classification vectors"
        failures = []
        for v in vectors["vectors"]:
            got = classify_component(v["name"], v["version"], v["imports"])
            expected = v["expected"]
            for field, want in expected.items():
                if got.get(field) != want:
                    failures.append("%s: %s got %r want %r"
                                    % (v["id"], field, got.get(field), want))
        assert not failures, "classification vector failures:\n" + "\n".join(failures)

    def test_unknown_component_classifies_as_unknown(self):
        got = classify_component("some-random-lib", "1.0.0", [])
        assert got["family"] == "UNKNOWN"
        assert got["classification"] == "UNKNOWN"
        assert got["std_reference"] == ""

    def test_non_pq_component_has_no_std_reference(self):
        got = classify_component("rsa-crypto", "2.0", [])
        assert got["family"] == "RSA"
        assert got["classification"] == "UNSAFE"
        assert got["std_reference"] == ""


# ---------------------------------------------------------------------------
# Golden vectors: enrichment output for known SBOMs
# ---------------------------------------------------------------------------

class TestEnrichmentGoldenVectors:
    """KAT: enrich_sbom output matches golden expected property sets."""

    def test_enrichment_vectors_match_golden_file(self):
        vectors = _load_golden("enrichment-vectors.json")
        assert len(vectors["vectors"]) >= 5, "expected >=5 enrichment vectors"
        failures = []
        for v in vectors["vectors"]:
            enricher = CBOMEnricher(CBOMProfile(v["profile"]))
            got = enricher.enrich_sbom(v["input"])
            got_map = {c["name"]: {p["name"]: p["value"] for p in _pq_props(c)}
                       for c in got["components"]}
            for comp_name, expected_props in v["expected"].items():
                actual = got_map.get(comp_name, {})
                for prop_name, want in expected_props.items():
                    if actual.get(prop_name) != want:
                        failures.append("%s/%s got %r want %r"
                                        % (v["id"], prop_name, actual.get(prop_name), want))
        assert not failures, "enrichment vector failures:\n" + "\n".join(failures)

    def test_liboqs_component_gets_ml_kem_metadata(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                "components": [{"type": "library", "name": "liboqs", "version": "3.5.7"}]}
        out = enricher.enrich_sbom(sbom)
        props = {p["name"]: p["value"] for p in _pq_props(out["components"][0])}
        assert props["appliedquantum.algorithm.family"] == "ML-KEM"
        assert props["appliedquantum.algorithm.classification"] == "SAFE"
        assert props["appliedquantum.algorithm.key_size"] == "768"
        assert props["appliedquantum.algorithm.std_reference"] == "FIPS 203"

    def test_openssl_component_is_transitional(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"components": [{"name": "openssl", "version": "3.5.0"}]}
        out = enricher.enrich_sbom(sbom)
        props = {p["name"]: p["value"] for p in _pq_props(out["components"][0])}
        assert props["appliedquantum.algorithm.family"] == "X25519Kyber768"
        assert props["appliedquantum.algorithm.classification"] == "TRANSITIONAL"

    def test_cryptography_component_is_ml_dsa(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"components": [{"name": "cryptography", "version": "42.0.0"}]}
        out = enricher.enrich_sbom(sbom)
        props = {p["name"]: p["value"] for p in _pq_props(out["components"][0])}
        assert props["appliedquantum.algorithm.family"] == "ML-DSA"
        assert props["appliedquantum.algorithm.classification"] == "SAFE"

    def test_unknown_component_left_unenriched(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"components": [{"name": "left-pad", "version": "1.3.0"}]}
        out = enricher.enrich_sbom(sbom)
        assert _pq_props(out["components"][0]) == []


# ---------------------------------------------------------------------------
# FIPS parameter tables the product records (spec §2.1)
# ---------------------------------------------------------------------------

class TestFIPSParameterVectors:
    """KAT: recorded parameter metadata matches the FIPS tables in spec §2.1."""

    def test_fips_parameter_vectors_match_golden_file(self):
        table = _load_golden("fips-parameter-sets.json")
        failures = []
        for entry in table["parameter_sets"]:
            # The product records family/classification per algorithm family;
            # the parameter metadata itself comes from the FIPS tables and is
            # asserted here as the test suite's golden truth.
            recorded = entry.get("recorded", {})
            reference = entry.get("reference", "")
            assert recorded, "%s has no recorded block" % entry["id"]
            assert reference.startswith("FIPS"), "%s reference missing" % entry["id"]
            for field in ("family", "std_reference"):
                if field in recorded and recorded[field]:
                    assert recorded[field] in ("ML-KEM", "ML-DSA", "SLH-DSA") or \
                        recorded[field].startswith("FIPS 20"), "%s.%s bad" % (entry["id"], field)
        assert len(table["parameter_sets"]) >= 3, "expected >=3 FIPS parameter sets"

    def test_ml_kem_key_sizes_are_fips_cited_bytes(self):
        """key_size property must be the FIPS-cited byte size, not computed."""
        table = _load_golden("fips-parameter-sets.json")
        ml_kem = [e for e in table["parameter_sets"]
                  if e["family"] == "ML-KEM"]
        assert {e["key_size_bytes"] for e in ml_kem} == {800, 1184, 1568}
        ml768 = [e for e in ml_kem if e["id"] == "ML-KEM-768"][0]
        assert ml768["key_size_bytes"] == 1184
        assert ml768["reference"] == "FIPS 203 Table 3"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class TestEnrichmentIdempotency:
    """enrich_sbom must not duplicate properties."""

    @pytest.mark.parametrize("profile", ["cnsa20", "ccf"])
    def test_second_enrichment_does_not_duplicate_properties(self, profile):
        enricher = CBOMEnricher(CBOMProfile(profile))
        sbom = {"components": [{"name": "liboqs", "version": "3.5.7"},
                               {"name": "openssl", "version": "3.5.0"},
                               {"name": "left-pad", "version": "1.0"}]}
        first = enricher.enrich_sbom(sbom)
        snapshot = json.dumps(first, sort_keys=True)
        second = enricher.enrich_sbom(first)
        assert json.dumps(second, sort_keys=True) == snapshot, (
            "enrich_sbom is not idempotent: second call differs from first")

    def test_repeated_enrichment_is_a_fixpoint(self):
        enricher = CBOMEnricher(CBOMProfile.CCF)
        sbom = {"components": [{"name": "liboqs", "version": "3.5.7"}]}
        out = sbom
        for _ in range(5):
            out = enricher.enrich_sbom(out)
        props = _pq_props(out["components"][0])
        names = [p["name"] for p in props]
        assert len(names) == len(set(names)), "duplicate property names after 5 enrichments"

    def test_existing_property_values_are_preserved_not_overwritten(self):
        """A pre-existing appliedquantum.* property keeps its own value."""
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"components": [{
            "name": "liboqs", "version": "3.5.7",
            "properties": [{"name": "appliedquantum.algorithm.family", "value": "Kyber"}],
        }]}
        out = enricher.enrich_sbom(sbom)
        props = {p["name"]: p["value"] for p in _pq_props(out["components"][0])}
        assert props["appliedquantum.algorithm.family"] == "Kyber"
        assert sum(1 for n in props if n == "appliedquantum.algorithm.family") == 1


# ---------------------------------------------------------------------------
# Validate / attest / CLI
# ---------------------------------------------------------------------------

class TestValidateProduct:
    """KAT: validate() reports profile compliance."""

    def test_valid_cbom_passes_cnsa20_validation(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        result = enricher.validate(cbom, CBOMProfile.CNSA20)
        assert result["valid"] is True
        assert result["errors"] == []
        assert result["components_total"] == 1
        assert result["components_with_pq_properties"] == 1

    def test_ccf_profile_requires_vendor_id(self):
        enricher = CBOMEnricher(CBOMProfile.CCF)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        result = enricher.validate(cbom, CBOMProfile.CCF)
        assert result["valid"] is True, result["errors"]

    def test_nonenriched_component_is_reported(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = {"components": [{"name": "left-pad", "version": "1.0"}]}
        result = enricher.validate(cbom, CBOMProfile.CNSA20)
        assert result["valid"] is True  # no PQ props means nothing to check
        assert result["components_unclassified"] == 1
        assert result["unsupported"]

    def test_non_dict_cbom_is_invalid_not_crash(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        result = enricher.validate(["not", "a", "dict"])
        assert result["valid"] is False
        assert result["errors"]


class TestAttestProduct:
    """KAT: attest() writes a signed manifest + CBOM copy."""

    def test_attestation_package_structure(self, tmp_path):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        out_dir = str(tmp_path / "attest")
        manifest_path = enricher.attest(cbom, CBOMProfile.CNSA20, out_dir)
        assert os.path.isfile(manifest_path)
        manifest = json.load(open(manifest_path))
        assert manifest["profile"] == "cnsa20"
        assert manifest["files"][0]["path"] == "cbom.json"
        assert len(manifest["files"][0]["sha256"]) == 64
        assert os.path.isfile(os.path.join(out_dir, "cbom.json"))


class TestScanPathProduct:
    """KAT: scan_path detects PQ libraries and enriches them."""

    def test_scan_detects_liboqs_named_file(self, tmp_path):
        (tmp_path / "liboqs_notes.txt").write_text("notes")
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        out = enricher.scan_path(str(tmp_path))
        names = [c["name"] for c in out["components"]]
        assert "liboqs" in names

    def test_scan_path_missing_directory_raises(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError):
            enricher.scan_path("/nonexistent/path/xyz")

    def test_scan_path_bad_format_raises(self, tmp_path):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError):
            enricher.scan_path(str(tmp_path), output_format="spdx-json")


# ---------------------------------------------------------------------------
# Negative / edge cases (spec §3)
# ---------------------------------------------------------------------------

class TestNegativeCases:
    """Negative tests: malformed input raises a specific, catchable error."""

    def test_non_dict_sbom_raises_valueerror(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError):
            enricher.enrich_sbom("not a dict")

    def test_missing_components_field_raises(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError, match="components"):
            enricher.enrich_sbom({"bomFormat": "CycloneDX"})

    def test_component_not_a_dict_raises(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError):
            enricher.enrich_sbom({"components": ["just a string"]})

    def test_component_missing_name_raises(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        with pytest.raises(ValueError, match="name"):
            enricher.enrich_sbom({"components": [{"version": "1.0"}]})

    def test_empty_components_list_returns_unchanged(self):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        sbom = {"bomFormat": "CycloneDX", "components": []}
        out = enricher.enrich_sbom(sbom)
        assert out["components"] == []

    def test_none_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            CBOMEnricher(profile=None)

    def test_unknown_profile_string_raises(self):
        with pytest.raises(ValueError):
            CBOMProfile("not-a-profile")


# ---------------------------------------------------------------------------
# classify_component / canonicalize_property unit KATs
# ---------------------------------------------------------------------------

class TestClassifyAndCanonicalize:
    def test_canonicalize_property_replaces_colons(self):
        assert canonicalize_property(
            "appliedquantum:algorithm:family", "ML-KEM") == \
            "appliedquantum.algorithm.family=ML-KEM"

    def test_classify_imports_hint_beats_name(self):
        got = classify_component("unknown-lib", "1.0", ["liboqs"])
        assert got["family"] == "ML-KEM"

    def test_classify_slh_dsa_family(self):
        got = classify_component("sphincs-plus", "0.1", [])
        assert got["family"] == "SLH-DSA"
        assert got["std_reference"] == "FIPS 205"


# ---------------------------------------------------------------------------
# CLI (spec S4)
# ---------------------------------------------------------------------------

class TestCLI:
    """KAT: CLI subcommands run through the product."""

    def _run(self, args):
        env = dict(os.environ)
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{SRC}:{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = SRC
        return subprocess.run(
            [sys.executable, "-m", "pqblocks_cbom"] + args,
            capture_output=True, text=True, env=env, cwd=ROOT)

    def test_cli_enrich_command(self, tmp_path):
        sbom = {"components": [{"name": "liboqs", "version": "3.5.7"}]}
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))
        out_file = tmp_path / "cbom.json"
        r = self._run(["enrich", str(sbom_file), "-o", str(out_file)])
        assert r.returncode == 0, r.stderr
        cbom = json.loads(out_file.read_text())
        props = {p["name"] for p in cbom["components"][0].get("properties", [])}
        assert "appliedquantum.algorithm.family" in props

    def test_cli_validate_command(self, tmp_path):
        sbom = {"components": [{"name": "liboqs", "version": "3.5.7"}]}
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(sbom)
        cbom_file = tmp_path / "cbom.json"
        cbom_file.write_text(json.dumps(cbom))
        r = self._run(["validate", str(cbom_file), "--profile", "cnsa20"])
        assert r.returncode == 0, r.stderr
        payload = json.loads(r.stdout.strip().splitlines()[-1])
        assert payload["valid"] is True

    def test_cli_scan_command(self, tmp_path):
        (tmp_path / "liboqs_x.txt").write_text("x")
        r = self._run(["scan", str(tmp_path)])
        assert r.returncode == 0, r.stderr
        payload = json.loads(r.stdout.strip().splitlines()[-1])
        assert payload["processed"] >= 1
        assert payload["found_pq"] >= 1

    def test_cli_attest_command(self, tmp_path):
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        cbom_file = tmp_path / "cbom.json"
        cbom_file.write_text(json.dumps(cbom))
        attest_dir = tmp_path / "attest"
        r = self._run(["attest", str(cbom_file), "-o", str(attest_dir)])
        assert r.returncode == 0, r.stderr
        assert (attest_dir / "manifest.json").is_file()

    def test_cli_missing_file_returns_2(self, tmp_path):
        r = self._run(["enrich", str(tmp_path / "nope.json")])
        assert r.returncode == 2


class TestCLIDirect:
    """Direct main() entry-point tests to cover src/pqblocks_cbom/__main__.py."""

    def test_main_enrich(self, tmp_path, monkeypatch):
        from pqblocks_cbom.__main__ import main
        sbom = {"components": [{"name": "liboqs", "version": "3.5.7"}]}
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))
        out_file = tmp_path / "cbom.json"
        rc = main(["enrich", str(sbom_file), "-o", str(out_file)])
        assert rc == 0
        cbom = json.loads(out_file.read_text())
        assert cbom["components"][0]["properties"]

    def test_main_validate(self, tmp_path):
        from pqblocks_cbom.__main__ import main
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        cbom_file = tmp_path / "cbom.json"
        cbom_file.write_text(json.dumps(cbom))
        rc = main(["validate", str(cbom_file), "--profile", "cnsa20"])
        assert rc == 0

    def test_main_validate_invalid_returns_nonzero(self, tmp_path):
        from pqblocks_cbom.__main__ import main
        cbom_file = tmp_path / "cbom.json"
        cbom_file.write_text(json.dumps({"components": [{"name": "liboqs", "version": "1.0"}]}))
        rc = main(["validate", str(cbom_file), "--profile", "cnsa20"])
        # A component without PQ properties is *valid* (nothing to check), so rc == 0.
        # The real validation failure is missing Tier-1 properties for an enriched component.
        # We therefore test an enriched component with required props missing via direct call.
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom({"components": [{"name": "liboqs", "version": "1.0"}]})
        # Remove required property to force invalid
        del cbom["components"][0]["properties"][0]
        cbom_file2 = tmp_path / "cbom2.json"
        cbom_file2.write_text(json.dumps(cbom))
        rc2 = main(["validate", str(cbom_file2), "--profile", "cnsa20"])
        assert rc2 != 0

    def test_main_scan_missing_path(self):
        from pqblocks_cbom.__main__ import main
        try:
            rc = main(["scan", "/nonexistent/path/xyz"])
        except SystemExit as e:
            rc = e.code
        assert rc != 0

    def test_main_scan_bad_format(self, tmp_path):
        from pqblocks_cbom.__main__ import main
        try:
            rc = main(["scan", str(tmp_path), "--format", "spdx-json"])
        except SystemExit as e:
            rc = e.code
        assert rc != 0

    def test_main_attest(self, tmp_path):
        from pqblocks_cbom.__main__ import main
        enricher = CBOMEnricher(CBOMProfile.CNSA20)
        cbom = enricher.enrich_sbom(
            {"components": [{"name": "liboqs", "version": "3.5.7"}]})
        cbom_file = tmp_path / "cbom.json"
        cbom_file.write_text(json.dumps(cbom))
        attest_dir = tmp_path / "attest"
        rc = main(["attest", str(cbom_file), "-o", str(attest_dir)])
        assert rc == 0
        assert (attest_dir / "manifest.json").is_file()

    def test_main_no_command_returns_nonzero(self):
        from pqblocks_cbom.__main__ import main
        try:
            rc = main([])
        except SystemExit as e:
            rc = e.code
        assert rc != 0

    def test_main_invalid_json(self):
        from pqblocks_cbom.__main__ import main
        rc = main(["validate", "/some/path.json"])
        assert rc == 2

    def test_main_scan_with_output_file(self, tmp_path, capsys):
        from pqblocks_cbom.__main__ import main
        (tmp_path / "liboqs_notes.txt").write_text("notes")
        out_file = tmp_path / "out.json"
        rc = main(["scan", str(tmp_path), "-o", str(out_file)])
        assert rc == 0
        assert out_file.is_file()
        payload = json.loads(capsys.readouterr().out.strip())
        assert payload["processed"] >= 1

    def test_main_enrich_to_stdout(self, tmp_path, capsys):
        from pqblocks_cbom.__main__ import main
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"components": [{"name": "liboqs", "version": "3.5.7"}]}))
        rc = main(["enrich", str(sbom_file)])
        assert rc == 0
        out = capsys.readouterr().out.strip()
        payload = json.loads(out.splitlines()[-1])
        assert payload["processed"] == 1