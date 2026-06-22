from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable

from .findings import Finding
from .registry import RuleSpec

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}


def severity_at_least(severity: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER[threshold]


def findings_to_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True)


def findings_to_markdown(findings: Iterable[Finding]) -> str:
    materialized = list(findings)
    if not materialized:
        return "# Kube ClusterGuard Report\n\nNo findings.\n"

    lines = [
        "# Kube ClusterGuard Report",
        "",
        "| Severity | Rule | Category | Source | Resource | Finding | Remediation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in materialized:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(finding.severity),
                    _md(finding.rule_id),
                    _md(finding.category),
                    _md(finding.source or "-"),
                    _md(finding.resource),
                    _md(finding.message),
                    _md(finding.remediation),
                ]
            )
            + " |"
        )

    counts = Counter(finding.severity for finding in materialized)
    lines.extend(["", "## Summary", ""])
    for severity in ("critical", "high", "medium", "low"):
        if counts[severity]:
            lines.append(f"- {severity}: {counts[severity]}")
    return "\n".join(lines) + "\n"


def findings_to_sarif(findings: Iterable[Finding]) -> str:
    materialized = list(findings)
    rule_lookup = {
        finding.rule_id: {
            "id": finding.rule_id,
            "name": finding.category,
            "shortDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
        }
        for finding in materialized
    }
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kube-clusterguard",
                        "informationUri": "https://github.com/aivinay/kube-clusterguard",
                        "rules": list(rule_lookup.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.source or finding.resource},
                                }
                            }
                        ],
                    }
                    for finding in materialized
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def rules_to_json(rules: Iterable[RuleSpec]) -> str:
    return json.dumps([rule.to_dict() for rule in rules], indent=2, sort_keys=True)


def rules_to_markdown(rules: Iterable[RuleSpec]) -> str:
    lines = [
        "# Kube ClusterGuard Rules",
        "",
        "| Rule | Severity | Category | Title | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rule in rules:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(rule.rule_id),
                    _md(rule.default_severity),
                    _md(rule.category),
                    _md(rule.title),
                    _md(rule.remediation),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
