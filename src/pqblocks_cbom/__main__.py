"""CLI entry point for pqblocks-cbom."""

import argparse
import json
import sys
from typing import List, Optional

from .enricher import CBOMEnricher, CBOMProfile


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqblocks-cbom",
        description="Enrich CycloneDX SBOMs with post-quantum metadata"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Global options
    for sp in [subparsers]:
        pass

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan source path and generate enriched CBOM")
    scan_parser.add_argument("path", help="Path to source code")
    scan_parser.add_argument("--profile", choices=["cnsa20", "ccf"], default="cnsa20",
                            help="CBOM Profile (default: cnsa20)")
    scan_parser.add_argument("--format", choices=["cyclonedx-json"], default="cyclonedx-json",
                            help="Output format")
    scan_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    scan_parser.add_argument("--json", action="store_true", default=True,
                            help="Output JSON summary to stdout")

    # enrich command
    enrich_parser = subparsers.add_parser("enrich", help="Enrich existing SBOM with PQ metadata")
    enrich_parser.add_argument("sbom_file", help="Path to SBOM JSON file")
    enrich_parser.add_argument("--profile", choices=["cnsa20", "ccf"], default="cnsa20",
                              help="CBOM Profile (default: cnsa20)")
    enrich_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    enrich_parser.add_argument("--json", action="store_true", default=True,
                              help="Output JSON summary to stdout")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate CBOM against profile")
    validate_parser.add_argument("cbom_file", help="Path to CBOM JSON file")
    validate_parser.add_argument("--profile", choices=["cnsa20", "ccf"], default="cnsa20",
                                help="CBOM Profile (default: cnsa20)")
    validate_parser.add_argument("--json", action="store_true", default=True,
                                help="Output JSON validation result to stdout")

    # attest command
    attest_parser = subparsers.add_parser("attest", help="Generate attestation package")
    attest_parser.add_argument("cbom_file", help="Path to CBOM JSON file")
    attest_parser.add_argument("--profile", choices=["cnsa20", "ccf"], default="cnsa20",
                              help="CBOM Profile (default: cnsa20)")
    attest_parser.add_argument("--output", "-o", required=True,
                              help="Output directory for attestation package")

    args = parser.parse_args(argv)

    # Map profile strings to enums
    profile_map = {
        "cnsa20": CBOMProfile.CNSA20,
        "ccf": CBOMProfile.CCF
    }
    profile = profile_map[args.profile]
    enricher = CBOMEnricher(profile=profile)

    try:
        if args.command == "scan":
            cbom = enricher.scan_path(args.path, output_format=args.format)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(cbom, f, indent=2)
            if args.json:
                result = {
                    "processed": len(cbom.get('components', [])),
                    "found_pq": sum(1 for c in cbom.get('components', [])
                                   if any(p.get('name', '').startswith('appliedquantum.')
                                         for p in c.get('properties', []))),
                    "valid": True,
                    "errors": []
                }
                print(json.dumps(result))
            return 0

        elif args.command == "enrich":
            with open(args.sbom_file, 'r') as f:
                sbom = json.load(f)
            cbom = enricher.enrich_sbom(sbom)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(cbom, f, indent=2)
            if args.json:
                result = {
                    "processed": len(cbom.get('components', [])),
                    "found_pq": sum(1 for c in cbom.get('components', [])
                                   if any(p.get('name', '').startswith('appliedquantum.')
                                         for p in c.get('properties', []))),
                    "valid": True,
                    "errors": []
                }
                print(json.dumps(result))
            return 0

        elif args.command == "validate":
            with open(args.cbom_file, 'r') as f:
                cbom = json.load(f)
            validation = enricher.validate(cbom, profile)
            if args.json:
                print(json.dumps(validation))
            return 0 if validation["valid"] else 1

        elif args.command == "attest":
            with open(args.cbom_file, 'r') as f:
                cbom = json.load(f)
            manifest_path = enricher.attest(cbom, profile, args.output)
            return 0

    except FileNotFoundError as e:
        print(json.dumps({"valid": False, "errors": [f"File not found: {e}"]}), file=sys.stderr)
        return 2
    except ValueError as e:
        print(json.dumps({"valid": False, "errors": [str(e)]}), file=sys.stderr)
        return 2
    except Exception as e:
        print(json.dumps({"valid": False, "errors": [f"Unexpected error: {e}"]}), file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())