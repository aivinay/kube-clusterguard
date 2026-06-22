from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from .findings import Finding


@dataclass(frozen=True)
class Suppression:
    rule_id: str = "*"
    resource: str = "*"
    reason: str = ""


@dataclass(frozen=True)
class GuardrailPolicy:
    disabled_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    suppressions: list[Suppression] = field(default_factory=list)


DEFAULT_POLICY = """# Kube ClusterGuard policy
disabled_rules: []
severity_overrides: {}
suppressions:
  # - rule_id: CG003
  #   resource: Service/ml/notebook
  #   reason: "Documented temporary exposure."
"""


def load_policy(path: Path | None) -> GuardrailPolicy:
    if path is None:
        return GuardrailPolicy()

    text = path.read_text(encoding="utf-8")
    payload = yaml.safe_load(text) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if payload is None:
        return GuardrailPolicy()
    if not isinstance(payload, dict):
        raise ValueError("Policy file must contain a mapping.")

    return GuardrailPolicy(
        disabled_rules=set(_string_list(payload.get("disabled_rules", []))),
        severity_overrides={
            str(rule_id): str(severity)
            for rule_id, severity in dict(payload.get("severity_overrides", {})).items()
        },
        suppressions=[
            Suppression(
                rule_id=str(suppression.get("rule_id", "*")),
                resource=str(suppression.get("resource", "*")),
                reason=str(suppression.get("reason", "")),
            )
            for suppression in _dict_list(payload.get("suppressions", []))
        ],
    )


def apply_policy(findings: list[Finding], policy: GuardrailPolicy) -> list[Finding]:
    filtered: list[Finding] = []
    for finding in findings:
        if finding.rule_id in policy.disabled_rules:
            continue
        if _is_suppressed(finding, policy.suppressions):
            continue
        severity = policy.severity_overrides.get(finding.rule_id, finding.severity)
        filtered.append(replace(finding, severity=severity))
    return filtered


def write_default_policy(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Policy file already exists: {path}")
    path.write_text(DEFAULT_POLICY, encoding="utf-8")


def _is_suppressed(finding: Finding, suppressions: list[Suppression]) -> bool:
    return any(
        fnmatch(finding.rule_id, suppression.rule_id)
        and fnmatch(finding.resource, suppression.resource)
        for suppression in suppressions
    )


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("Expected a list of strings.")
    return [str(item) for item in value]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("Expected a list of mappings.")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("Expected a list of mappings.")
    return value
