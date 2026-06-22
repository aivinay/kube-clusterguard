from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .policy import apply_policy, load_policy, write_default_policy
from .registry import RULES
from .reports import (
    findings_to_json,
    findings_to_markdown,
    findings_to_sarif,
    rules_to_json,
    rules_to_markdown,
    severity_at_least,
)
from .scanner import scan_paths


def main() -> None:
    raise SystemExit(run())


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clusterguard")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan Kubernetes JSON or YAML manifests.")
    scan.add_argument(
        "manifest",
        nargs="+",
        type=Path,
        help="Manifest files or directories to scan.",
    )
    scan.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
    )
    scan.add_argument(
        "--config",
        type=Path,
        help="Optional JSON/YAML policy file with suppressions and overrides.",
    )

    rules = subparsers.add_parser("rules", help="List built-in guardrail rules.")
    rules.add_argument("--format", choices=["json", "markdown"], default="markdown")

    config = subparsers.add_parser("config", help="Configuration helpers.")
    config_subparsers = config.add_subparsers(dest="config_command", required=True)
    init = config_subparsers.add_parser("init", help="Write a starter policy file.")
    init.add_argument("--output", "-o", type=Path, default=Path("clusterguard-policy.yaml"))
    init.add_argument("--force", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "scan":
        findings = apply_policy(scan_paths(args.manifest), load_policy(args.config))
        if args.format == "markdown":
            print(findings_to_markdown(findings), end="")
        elif args.format == "sarif":
            print(findings_to_sarif(findings))
        else:
            print(findings_to_json(findings))
        if any(severity_at_least(finding.severity, args.fail_on) for finding in findings):
            return 2
    elif args.command == "rules":
        if args.format == "json":
            print(rules_to_json(RULES))
        else:
            print(rules_to_markdown(RULES), end="")
    elif args.command == "config" and args.config_command == "init":
        write_default_policy(args.output, force=args.force)
    return 0


if __name__ == "__main__":
    main()
