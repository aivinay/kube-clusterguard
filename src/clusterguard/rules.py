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
        if kind in {"Job", "CronJob"}:
            findings.extend(_scan_job(resource, kind, pod_spec, name))

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

    containers = _containers(pod_spec)
    gpu_containers = [container for container in containers if _container_requests_gpu(container)]

    if gpu_containers and not _has_node_targeting(pod_spec):
        findings.append(
            Finding(
                rule_id="CG009",
                severity="medium",
                resource=resource_name,
                message="GPU workload has no nodeSelector, node affinity, or tolerations.",
                remediation=(
                    "Add a nodeSelector, node affinity, or tolerations so GPU pods schedule onto "
                    "GPU-capable, tainted nodes."
                ),
                category="gpu-governance",
            )
        )

    if gpu_containers and not _has_shared_memory_volume(pod_spec):
        findings.append(
            Finding(
                rule_id="CG010",
                severity="low",
                resource=resource_name,
                message="GPU workload has no in-memory shared-memory volume for data loaders.",
                remediation=(
                    "Mount an emptyDir volume with medium set to Memory at /dev/shm for "
                    "multi-worker data loaders."
                ),
                category="reliability",
            )
        )

    for container in containers:
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

        if _container_requests_gpu(container):
            if "ephemeral-storage" not in requests or "ephemeral-storage" not in limits:
                findings.append(
                    Finding(
                        rule_id="CG011",
                        severity="low",
                        resource=f"{resource_name}/{container_name}",
                        message="GPU container does not set ephemeral-storage requests and limits.",
                        remediation=(
                            "Set ephemeral-storage requests and limits to bound dataset and "
                            "checkpoint usage."
                        ),
                        category="resource-governance",
                    )
                )

            for gpu_key in _gpu_keys(limits):
                if gpu_key in requests and str(requests[gpu_key]) != str(limits[gpu_key]):
                    findings.append(
                        Finding(
                            rule_id="CG013",
                            severity="medium",
                            resource=f"{resource_name}/{container_name}",
                            message=(
                                f"GPU request and limit differ for {gpu_key} "
                                f"({requests[gpu_key]} vs {limits[gpu_key]})."
                            ),
                            remediation="Set equal GPU requests and limits for each accelerator.",
                            category="gpu-governance",
                        )
                    )
                    break

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


_GPU_RESOURCE_HINTS = ("nvidia.com/", "amd.com/", "gpu.intel.com/", "habana.ai/")


def _gpu_keys(quantities: Resource) -> list[str]:
    keys: list[str] = []
    for key in quantities:
        text = str(key)
        if "gpu" in text.lower() or text.startswith(_GPU_RESOURCE_HINTS):
            keys.append(text)
    return keys


def _container_requests_gpu(container: Resource) -> bool:
    resources = _mapping(container.get("resources"))
    return bool(
        _gpu_keys(_mapping(resources.get("limits")))
        or _gpu_keys(_mapping(resources.get("requests")))
    )


def _has_node_targeting(pod_spec: Resource) -> bool:
    if pod_spec.get("nodeSelector") or pod_spec.get("tolerations"):
        return True
    return bool(_mapping(pod_spec.get("affinity")).get("nodeAffinity"))


def _has_shared_memory_volume(pod_spec: Resource) -> bool:
    for volume in pod_spec.get("volumes", []) or []:
        empty_dir = _mapping(_mapping(volume).get("emptyDir"))
        if str(empty_dir.get("medium", "")).lower() == "memory":
            return True
    return False


def _scan_job(
    resource: Resource, kind: str, pod_spec: Resource, resource_name: str
) -> list[Finding]:
    if not any(_container_requests_gpu(container) for container in _containers(pod_spec)):
        return []

    job_spec = _mapping(resource.get("spec"))
    if kind == "CronJob":
        job_spec = _mapping(_mapping(job_spec.get("jobTemplate")).get("spec"))

    if "activeDeadlineSeconds" in job_spec or "backoffLimit" in job_spec:
        return []

    return [
        Finding(
            rule_id="CG012",
            severity="medium",
            resource=resource_name,
            message="GPU job sets neither activeDeadlineSeconds nor backoffLimit.",
            remediation=(
                "Set activeDeadlineSeconds and backoffLimit so failed GPU jobs stop instead of "
                "consuming accelerators on repeated retries."
            ),
            category="reliability",
        )
    ]


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
