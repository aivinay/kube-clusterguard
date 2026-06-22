from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    default_severity: str
    category: str
    title: str
    description: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "default_severity": self.default_severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }


RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="CG001",
        default_severity="medium",
        category="resource-governance",
        title="Missing resource requests or limits",
        description="Container resources do not define both requests and limits.",
        remediation="Set CPU, memory, and accelerator requests and limits.",
    ),
    RuleSpec(
        rule_id="CG002",
        default_severity="high",
        category="pod-security",
        title="Privileged runtime or host namespace exposure",
        description="Workload uses privileged mode or host-level network, PID, or IPC namespaces.",
        remediation=(
            "Disable privileged mode and host namespaces unless there is a documented node "
            "dependency."
        ),
    ),
    RuleSpec(
        rule_id="CG003",
        default_severity="medium",
        category="network-exposure",
        title="Public or node-level service exposure",
        description="Service uses LoadBalancer or NodePort exposure.",
        remediation="Prefer ClusterIP by default and require explicit exposure review.",
    ),
    RuleSpec(
        rule_id="CG004",
        default_severity="medium",
        category="supply-chain",
        title="Mutable or implicit image tag",
        description="Container image uses latest or omits an explicit tag.",
        remediation="Pin images to immutable version tags or digests.",
    ),
    RuleSpec(
        rule_id="CG005",
        default_severity="medium",
        category="identity",
        title="Service account token automounting",
        description="Workload explicitly automounts a Kubernetes service account token.",
        remediation=(
            "Disable automountServiceAccountToken unless the workload needs Kubernetes API "
            "access."
        ),
    ),
    RuleSpec(
        rule_id="CG006",
        default_severity="medium",
        category="pod-security",
        title="Root execution or privilege escalation",
        description="Container does not require non-root execution or allows privilege escalation.",
        remediation="Set runAsNonRoot to true and allowPrivilegeEscalation to false.",
    ),
    RuleSpec(
        rule_id="CG007",
        default_severity="medium",
        category="gpu-governance",
        title="GPU limit without matching request",
        description="Container declares a GPU limit without an explicit GPU request.",
        remediation="Set matching GPU requests and limits so scheduling intent is clear.",
    ),
    RuleSpec(
        rule_id="CG008",
        default_severity="low",
        category="reliability",
        title="Missing service health probe",
        description="Container has neither a readiness nor liveness probe.",
        remediation=(
            "Add probes for long-running services so Kubernetes can route and recover safely."
        ),
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}
