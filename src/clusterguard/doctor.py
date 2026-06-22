from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .registry import RULES
from .scanner import scan_paths


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }


def run_diagnostics(manifest: Path | None = None) -> list[DoctorCheck]:
    checks = [
        _check_yaml_support(),
        _check_rule_catalog(),
    ]
    if manifest is not None:
        checks.append(_check_manifest_scan(manifest))
    return checks


def diagnostics_to_json(checks: list[DoctorCheck]) -> str:
    payload = {
        "passed": all(check.passed for check in checks),
        "checks": [check.to_dict() for check in checks],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def diagnostics_to_markdown(checks: list[DoctorCheck]) -> str:
    lines = [
        "# Kube ClusterGuard Doctor",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for check in checks:
        status = "pass" if check.passed else "fail"
        lines.append(f"| {check.name} | {status} | {check.detail} |")
    return "\n".join(lines) + "\n"


def _check_yaml_support() -> DoctorCheck:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return DoctorCheck("yaml", False, "PyYAML is not importable")
    return DoctorCheck("yaml", True, "PyYAML is importable")


def _check_rule_catalog() -> DoctorCheck:
    if not RULES:
        return DoctorCheck("rules", False, "no rules are registered")
    return DoctorCheck("rules", True, f"{len(RULES)} rules registered")


def _check_manifest_scan(manifest: Path) -> DoctorCheck:
    try:
        findings = scan_paths([manifest])
    except Exception as exc:
        return DoctorCheck("scan", False, str(exc))
    return DoctorCheck("scan", True, f"{len(findings)} findings produced")
