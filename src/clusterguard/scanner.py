from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from .findings import Finding
from .loaders import load_resources
from .rules import scan_resources

MANIFEST_SUFFIXES = {".json", ".yaml", ".yml"}


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in collect_manifest_paths(paths):
        resources = load_resources(path)
        findings.extend(replace(finding, source=str(path)) for finding in scan_resources(resources))
    return findings


def collect_manifest_paths(paths: Iterable[Path]) -> list[Path]:
    manifests: list[Path] = []
    for path in paths:
        if path.is_dir():
            manifests.extend(
                sorted(
                    child
                    for child in path.rglob("*")
                    if child.is_file() and child.suffix.lower() in MANIFEST_SUFFIXES
                )
            )
        elif path.is_file():
            if path.suffix.lower() not in MANIFEST_SUFFIXES:
                raise ValueError(f"Unsupported manifest extension: {path}")
            manifests.append(path)
        else:
            raise FileNotFoundError(f"Manifest path does not exist: {path}")

    if not manifests:
        raise ValueError("No JSON or YAML manifest files found.")
    return sorted(dict.fromkeys(manifests))
