# Kube ClusterGuard

Static guardrails for Kubernetes AI/ML compute clusters.

[![CI](https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml/badge.svg)](https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Kube ClusterGuard scans Kubernetes JSON and YAML manifests before they reach a
cluster. It catches common security, reliability, cost, and GPU-governance
issues that show up in ML platforms: exposed services, mutable image tags,
privileged workloads, missing resource controls, service account token exposure,
ambiguous GPU scheduling, and missing probes.

It is small by design: no cluster credentials, no admission controller, no
database. Run it locally, in CI, or against rendered manifests from Helm,
Kustomize, or your deployment pipeline.

## What It Does

- Scans JSON and YAML Kubernetes manifests.
- Accepts files or directories, including multi-document YAML.
- Parses Kubernetes objects, arrays, and `List` resources.
- Extracts pod specs from Pods, Deployments, StatefulSets, DaemonSets,
  ReplicaSets, Jobs, and CronJobs.
- Emits JSON, Markdown, and SARIF reports.
- Supports CI failure thresholds with `--fail-on`.
- Supports policy files for disabled rules, severity overrides, and explicit
  suppressions.
- Includes a built-in rule catalog with `clusterguard rules`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Get Started

Scan the included risky deployment:

```bash
clusterguard scan examples/risky-deployment.yaml --format markdown
```

Scan a directory recursively:

```bash
clusterguard scan examples/ --format json
```

Fail CI on high-severity findings:

```bash
clusterguard scan manifests/ --format sarif --fail-on high
```

Generate a starter policy file:

```bash
clusterguard config init --output clusterguard-policy.yaml
```

List built-in rules:

```bash
clusterguard rules
```

## Rule Set

| Rule | Severity | Category | Summary |
| --- | --- | --- | --- |
| CG001 | medium | resource-governance | Missing CPU, memory, or GPU requests/limits |
| CG002 | high | pod-security | Privileged runtime or host namespace exposure |
| CG003 | medium | network-exposure | Public or node-level service exposure |
| CG004 | medium | supply-chain | Mutable or implicit image tags |
| CG005 | medium | identity | Service account token automounting |
| CG006 | medium/high | pod-security | Root execution or privilege escalation |
| CG007 | medium | gpu-governance | GPU limits without matching requests |
| CG008 | low | reliability | Missing readiness/liveness probes |

See [docs/rules.md](docs/rules.md) for rationale and remediation guidance.

## Configuration

Policy files are optional JSON or YAML documents:

```yaml
disabled_rules: []
severity_overrides:
  CG003: high
suppressions:
  - rule_id: CG003
    resource: Service/ml/notebook
    reason: "Reviewed temporary exposure."
```

Suppression resources support shell-style wildcards. See
[docs/configuration.md](docs/configuration.md) for details.

## Proof

The release checks are intentionally reproducible from a clean checkout:

```bash
python -m unittest discover -s tests
ruff check .
python -m build
clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none
```

Current validation covers manifest loading, rule detection, clean manifests,
policy filtering, source attribution, report rendering, and CLI helper commands.
See [docs/validation.md](docs/validation.md).

## Documentation

| Start here | Go deeper |
| --- | --- |
| [CLI reference](docs/cli.md) | [Rule catalog](docs/rules.md) |
| [Configuration](docs/configuration.md) | [Validation notes](docs/validation.md) |
| [Roadmap](docs/roadmap.md) | [Release checklist](docs/release.md) |

## Scope

Kube ClusterGuard is a static manifest scanner. It does not replace admission
control, runtime security monitoring, cloud billing analysis, or a full
Kubernetes policy engine. Its job is to provide fast, explainable feedback before
manifests are applied.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
