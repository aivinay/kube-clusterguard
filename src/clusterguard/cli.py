from __future__ import annotations

import argparse
import json
from pathlib import Path

from .rules import scan_resource


def main() -> None:
    parser = argparse.ArgumentParser(prog="clusterguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a JSON Kubernetes resource.")
    scan.add_argument("manifest", type=Path)

    args = parser.parse_args()
    if args.command == "scan":
        resource = json.loads(args.manifest.read_text(encoding="utf-8"))
        findings = scan_resource(resource)
        print(json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
