# Architecture

Kube ClusterGuard is a local static-analysis pipeline for Kubernetes manifests.
It favors deterministic checks, clear rule metadata, and simple outputs that are
easy to wire into CI.

## Core Flow

```text
Input paths
  |
  v
Path collector
  |
  v
JSON/YAML loader
  |
  v
Resource normalizer
  |
  v
Rule scanner
  |
  v
Policy filter
  |
  v
JSON / Markdown / SARIF reports
```

## Layers

- `loaders.py`: parses JSON, YAML, multi-document YAML, arrays, and Kubernetes
  `List` resources.
- `scanner.py`: walks files and directories, attaches source paths, and sends
  resources to the rule engine.
- `rules.py`: contains deterministic guardrail checks over services, pods, and
  workload pod templates.
- `registry.py`: documents rule IDs, categories, severities, summaries, and
  remediation text.
- `policy.py`: applies disabled rules, severity overrides, and explicit
  suppressions.
- `reports.py`: renders JSON, Markdown, SARIF, and threshold comparisons.
- `doctor.py`: checks local dependencies, rule registration, and optional
  manifest scanability.

## Boundaries

Kube ClusterGuard intentionally does not read kubeconfig, call the Kubernetes
API, mutate manifests, or store results. Inputs are local files. Outputs go to
standard output unless the caller redirects them.
