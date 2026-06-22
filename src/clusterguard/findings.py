from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str
    category: str = "general"
    source: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "resource": self.resource,
            "message": self.message,
            "remediation": self.remediation,
        }
        if self.source:
            payload["source"] = self.source
        return payload
