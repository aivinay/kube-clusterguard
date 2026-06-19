# Kube ClusterGuard

Security, cost, and reliability guardrails for AI/ML compute clusters.

Kube ClusterGuard starts as a static scanner for Kubernetes resources that commonly show up in AI and ML platforms: GPU-backed deployments, Ray services, batch jobs, and shared infrastructure workloads. The long-term goal is a practical guardrail toolkit for catching expensive, risky, or unreliable cluster configuration before it reaches production.

## Current scope

- Scan structured Kubernetes resources for guardrail findings.
- Flag exposed `LoadBalancer` and `NodePort` services.
- Flag containers missing resource requests or limits.
- Flag privileged containers and host-network workloads.
- Flag mutable `latest` image tags.
- Provide a small CLI that reads JSON Kubernetes manifests.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests
```

Scan a JSON manifest:

```bash
clusterguard scan deployment.json
```

## Project direction

Kube ClusterGuard is designed to grow toward:

- YAML manifest support with multi-document parsing.
- Live Kubernetes cluster scanning.
- Ray cluster policy checks.
- GPU request, limit, utilization, and idle-cost reporting.
- CI-friendly SARIF and Markdown reports.
- Prometheus and Grafana integration for continuous guardrails.

See [docs/roadmap.md](docs/roadmap.md) for the initial milestones.
