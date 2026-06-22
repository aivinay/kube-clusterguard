<h1 align="center">Kube ClusterGuard</h1>

<p align="center"><strong>Static guardrails for Kubernetes AI/ML compute clusters.</strong></p>

<p align="center">
  <a href="https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml"><img src="https://github.com/aivinay/kube-clusterguard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <a href="#get-started">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#proof">Proof</a> ·
  <a href="#privacy-and-scope">Privacy</a> ·
  <a href="docs/">Docs</a>
</p>

---

> Kube ClusterGuard scans rendered Kubernetes manifests before they reach a
> cluster. It catches ML-platform risks that are easy to miss in review:
> exposed services, mutable image tags, privileged pods, missing resource
> controls, weak service-account defaults, ambiguous GPU scheduling, and missing
> probes.

It is intentionally small: no cluster credentials, no admission controller, no
database, and no runtime dependency on a Kubernetes API server. Run it locally,
in CI, or against Helm/Kustomize output as a fast quality gate.

## What It Does

- Scans JSON and YAML Kubernetes manifests, including multi-document YAML.
- Accepts files, directories, Kubernetes arrays, and `List` resources.
- Extracts pod templates from common workload controllers.
- Emits JSON, Markdown, and SARIF reports.
- Supports CI failure thresholds with `--fail-on`.
- Supports policy files for disabled rules, severity overrides, and suppressions.
- Provides a built-in rule catalog and `doctor` diagnostics.

## How It Works

```text
Manifest files/directories
  |
  v
Loader: JSON/YAML, multi-document, List resources
  |
  v
Resource scanner: services, pods, and workload pod templates
  |
  v
Rule registry: security, reliability, cost, identity, GPU governance
  |
  v
Policy layer: suppressions, disabled rules, severity overrides
  |
  v
Reports: JSON, Markdown, SARIF, CI exit codes
```

The core invariant: every finding is deterministic, source-attributed, and tied
to a documented rule with a remediation hint.

## Get Started

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

```bash
clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown
clusterguard rules --format markdown
clusterguard config init --output clusterguard-policy.yaml
```

Fail CI on high-severity findings:

```bash
clusterguard scan manifests/ --format sarif --fail-on high
```

Container smoke check:

```bash
docker build -t kube-clusterguard:dev .
docker run --rm kube-clusterguard:dev --version
```

## Proof

The current release is validated with unit tests, linting, package build checks,
CLI smoke checks, and a release-artifact workflow.

```bash
python -m unittest discover -s tests
ruff check .
python -m build
clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none
```

Validation covers manifest loading, source attribution, rule detection, clean
manifests, policy filtering, report rendering, SARIF output, configuration
helpers, and diagnostics. See [docs/validation.md](docs/validation.md).

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

## Privacy and Scope

Kube ClusterGuard reads local manifest files only. It does not connect to a
cluster, read kubeconfig credentials, send telemetry, or store scan results.

It is a static manifest scanner. It does not replace admission control, runtime
security monitoring, billing analysis, or a full Kubernetes policy engine. Its
job is fast, explainable feedback before manifests are applied.

## Documentation

| Start here | Go deeper |
| --- | --- |
| [CLI reference](docs/cli.md) | [Rule catalog](docs/rules.md) |
| [Configuration](docs/configuration.md) | [Architecture](docs/architecture.md) |
| [Validation notes](docs/validation.md) | [Reproducibility](docs/reproducibility.md) |
| [Release checklist](docs/release.md) | [Roadmap](docs/roadmap.md) |

## Development

```bash
make install
make check
```

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Vinay Gupta
