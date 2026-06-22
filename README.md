# Kube ClusterGuard

[![CI](https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml/badge.svg)](https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Static guardrails for Kubernetes manifests used in GPU-heavy and ML-oriented
clusters.

Manifests are easy to render and hard to review. Kube ClusterGuard gives platform
teams a fast preflight check for risks that tend to slip into ML infrastructure:
public notebook services, privileged training pods, mutable image tags, weak
service-account defaults, missing resource controls, GPU request/limit drift, and
workloads with no readiness signal.

It runs entirely against local JSON/YAML files. There is no kubeconfig access, no
cluster API call, no admission webhook, and no database.

## A Thirty-Second Scan

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown
```

Use it as a CI gate:

```bash
clusterguard scan manifests/ --format sarif --fail-on high
```

Or inspect the rule catalog before enabling it:

```bash
clusterguard rules --format markdown
```

## What Gets Checked

| Area | Examples |
| --- | --- |
| Resource governance | Missing CPU, memory, or GPU requests and limits |
| Pod security | Privileged containers, host namespaces, root execution |
| Exposure | `LoadBalancer` and `NodePort` services |
| Supply chain hygiene | Mutable image tags such as `latest` |
| Identity defaults | Service-account token automounting |
| GPU scheduling | GPU limits without matching requests |
| Reliability | Missing readiness or liveness probes |

Each finding carries a rule ID, severity, category, affected resource, optional
source path, and remediation text. See [docs/rules.md](docs/rules.md).

## Typical Workflow

1. Render manifests from Helm, Kustomize, Jsonnet, or your deployment pipeline.
2. Run `clusterguard scan` against the rendered files.
3. Review Markdown locally or publish SARIF/JSON in CI.
4. Add policy suppressions only for reviewed exceptions.
5. Fail the pipeline on the severity threshold your team is ready to enforce.

Starter policy:

```bash
clusterguard config init --output clusterguard-policy.yaml
```

```yaml
disabled_rules: []
severity_overrides:
  CG003: high
suppressions:
  - rule_id: CG003
    resource: Service/ml/notebook
    reason: "Reviewed temporary exposure."
```

## Input and Output

Kube ClusterGuard accepts individual files or directories. It handles JSON,
YAML, multi-document YAML, arrays, and Kubernetes `List` objects. Pod templates
are extracted from Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets,
Jobs, and CronJobs.

Output modes:

- `json` for automation
- `markdown` for local review and pull-request comments
- `sarif` for code-scanning integrations

## Release Confidence

The repository ships with unit tests, linting, package-build checks, CLI smoke
checks, a Dockerfile, and a release-artifact workflow.

```bash
python -m unittest discover -s tests
ruff check .
python -m build
clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none
```

Docker smoke:

```bash
docker build -t kube-clusterguard:dev .
docker run --rm kube-clusterguard:dev --version
```

## Project Boundaries

Kube ClusterGuard is a static manifest scanner. It does not replace admission
control, runtime security monitoring, cloud billing analysis, or a full policy
engine. Its job is narrow: provide deterministic, explainable feedback before
manifests are applied.

## Documentation

- [CLI reference](docs/cli.md)
- [Rule catalog](docs/rules.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Validation notes](docs/validation.md)
- [Reproducibility](docs/reproducibility.md)
- [Release checklist](docs/release.md)
- [Roadmap](docs/roadmap.md)

## Development

```bash
make install
make check
```

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Vinay Gupta
