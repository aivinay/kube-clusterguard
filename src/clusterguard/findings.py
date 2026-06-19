from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
            "remediation": self.remediation,
        }
