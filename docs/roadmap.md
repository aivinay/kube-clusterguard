# Roadmap

## Milestone 1: Static Guardrail Scanner

- Scan structured Kubernetes resources.
- Add core security, cost, and reliability findings.
- Provide JSON CLI output.
- Cover rules with unit tests.

## Milestone 2: Kubernetes Manifest Support

- Add YAML and multi-document parsing.
- Support recursive directory scans.
- Add severity filters and exit codes for CI.
- Generate Markdown reports.

## Milestone 3: Cluster-Aware Checks

- Add Kubernetes API client integration.
- Detect exposed services and risky namespaces.
- Inspect GPU resource requests and limits.
- Add Ray cluster-specific checks.

## Milestone 4: Cost And Reliability Signals

- Add idle GPU and overprovisioning heuristics.
- Integrate Prometheus metrics.
- Export dashboards for Grafana.
- Emit trend reports for repeated scans.
