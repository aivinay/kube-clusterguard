from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .findings import Finding

Resource = Mapping[str, Any]


def scan_resources(resources: Iterable[Resource]) -> list[Finding]:
    findings: list[Finding] = []
    for resource in resources:
        findings.extend(scan_resource(resource))
    return findings


def scan_resource(resource: Resource) -> list[Finding]:
    kind = str(resource.get("kind", "Unknown"))
    name = _resource_name(resource)
    findings: list[Finding] = []

    if kind == "Service":
        findings.extend(_scan_service(resource, name))

    pod_spec = _pod_spec_for(resource)
    if pod_spec:
        findings.extend(_scan_pod_spec(pod_spec, name))

    return findings


def _scan_service(resource: Resource, resource_name: str) -> list[Finding]:
    service_type = str(_mapping(resource.get("spec")).get("type", "ClusterIP"))
    if service_type not in {"LoadBalancer", "NodePort"}:
        return []

    return [
        Finding(
            rule_id="CG003",
            severity="medium",
            resource=resource_name,
            message=f"Service is exposed with type {service_type}.",
            remediation=(
                "Prefer ClusterIP by default and require an explicit exposure review for "
                "public services."
            ),
            category="network-exposure",
        )
    ]


def _scan_pod_spec(pod_spec: Resource, resource_name: str) -> list[Finding]:
    findings: list[Finding] = []

    if pod_spec.get("hostNetwork") is True:
        findings.append(
            Finding(
                rule_id="CG002",
                severity="high",
                resource=resource_name,
                message="Workload enables hostNetwork.",
                remediation=(
                    "Disable hostNetwork unless the workload has a documented node-network "
                    "dependency."
                ),
                category="pod-security",
            )
        )

    for namespace_field in ("hostPID", "hostIPC"):
        if pod_spec.get(namespace_field) is True:
            findings.append(
                Finding(
                    rule_id="CG002",
                    severity="high",
                    resource=resource_name,
                    message=f"Workload enables {namespace_field}.",
                    remediation=(
                        "Disable host namespace sharing unless the workload has a documented "
                        "node-level dependency."
                    ),
                    category="pod-security",
                )
            )

    if pod_spec.get("automountServiceAccountToken") is True:
        findings.append(
            Finding(
                rule_id="CG005",
                severity="medium",
                resource=resource_name,
                message="Workload explicitly automounts a service account token.",
                remediation=(
                    "Disable automountServiceAccountToken unless the workload needs Kubernetes "
                    "API access."
                ),
                category="identity",
            )
        )

    for container in _containers(pod_spec):
        container_name = str(container.get("name", "unnamed"))
        image = str(container.get("image", ""))
        security_context = _mapping(container.get("securityContext"))
        resources = _mapping(container.get("resources"))

        if image.endswith(":latest") or ":" not in image:
            findings.append(
                Finding(
                    rule_id="CG004",
                    severity="medium",
                    resource=f"{resource_name}/{container_name}",
                    message="Container image uses a mutable or implicit tag.",
                    remediation=(
                        "Pin images to immutable version tags or digests for reproducible "
                        "rollouts."
                    ),
                    category="supply-chain",
                )
            )

        if security_context.get("privileged") is True:
            findings.append(
                Finding(
                    rule_id="CG002",
                    severity="high",
                    resource=f"{resource_name}/{container_name}",
                    message="Container runs in privileged mode.",
                    remediation=(
                        "Remove privileged mode and grant only the specific Linux capabilities "
                        "required."
                    ),
                    category="pod-security",
                )
            )

        if security_context.get("allowPrivilegeEscalation") is True:
            findings.append(
                Finding(
                    rule_id="CG006",
                    severity="high",
                    resource=f"{resource_name}/{container_name}",
                    message="Container allows privilege escalation.",
                    remediation=(
                        "Set allowPrivilegeEscalation to false for least-privilege runtime "
                        "behavior."
                    ),
                    category="pod-security",
                )
            )

        if security_context.get("runAsNonRoot") is not True:
            findings.append(
                Finding(
                    rule_id="CG006",
                    severity="medium",
                    resource=f"{resource_name}/{container_name}",
                    message="Container does not require a non-root user.",
                    remediation=(
                        "Set runAsNonRoot to true and run with an explicit non-root UID where "
                        "possible."
                    ),
                    category="pod-security",
                )
            )

        if not resources.get("requests") or not resources.get("limits"):
            findings.append(
                Finding(
                    rule_id="CG001",
                    severity="medium",
                    resource=f"{resource_name}/{container_name}",
                    message="Container is missing resource requests or limits.",
                    remediation=(
                        "Set CPU, memory, and GPU requests and limits for predictable scheduling "
                        "and cost control."
                    ),
                    category="resource-governance",
                )
            )

        limits = _mapping(resources.get("limits"))
        requests = _mapping(resources.get("requests"))
        if "nvidia.com/gpu" in limits and "nvidia.com/gpu" not in requests:
            findings.append(
                Finding(
                    rule_id="CG007",
                    severity="medium",
                    resource=f"{resource_name}/{container_name}",
                    message="Container has a GPU limit without an explicit GPU request.",
                    remediation=(
                        "Set matching GPU requests and limits so scheduling intent is "
                        "unambiguous."
                    ),
                    category="gpu-governance",
                )
            )

        if "readinessProbe" not in container and "livenessProbe" not in container:
            findings.append(
                Finding(
                    rule_id="CG008",
                    severity="low",
                    resource=f"{resource_name}/{container_name}",
                    message="Container has no readiness or liveness probe.",
                    remediation=(
                        "Add probes for long-running services so Kubernetes can route and "
                        "recover safely."
                    ),
                    category="reliability",
                )
            )

    return findings


def _pod_spec_for(resource: Resource) -> Resource | None:
    kind = str(resource.get("kind", ""))
    spec = _mapping(resource.get("spec"))

    if kind == "Pod":
        return spec

    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        return _mapping(_mapping(_mapping(spec.get("template")).get("spec")))

    if kind == "Job":
        return _mapping(_mapping(_mapping(spec.get("template")).get("spec")))

    if kind == "CronJob":
        job_template = _mapping(_mapping(spec.get("jobTemplate")).get("spec"))
        return _mapping(_mapping(_mapping(job_template.get("template")).get("spec")))

    return None


def _containers(pod_spec: Resource) -> list[Resource]:
    containers = list(pod_spec.get("containers", []))
    init_containers = list(pod_spec.get("initContainers", []))
    return [_mapping(container) for container in containers + init_containers]


def _resource_name(resource: Resource) -> str:
    kind = str(resource.get("kind", "Unknown"))
    metadata = _mapping(resource.get("metadata"))
    name = str(metadata.get("name", "unnamed"))
    namespace = metadata.get("namespace")
    if namespace:
        return f"{kind}/{namespace}/{name}"
    return f"{kind}/{name}"


def _mapping(value: Any) -> Resource:
    if isinstance(value, Mapping):
        return value
    return {}
