# CLI Reference

Kube ClusterGuard exposes a small CLI designed for local review and CI.

## Version

```bash
clusterguard --version
```

## Doctor

```bash
clusterguard doctor
clusterguard doctor --manifest examples/risky-deployment.yaml --format json
```

Checks PyYAML availability, rule registration, and optional manifest scanability.
Returns exit code `1` if an installation or input check fails.

## Scan Manifests

```bash
clusterguard scan path/to/manifest.yaml
clusterguard scan manifests/ --format markdown
clusterguard scan manifests/ --format sarif --fail-on high
```

Inputs may be JSON/YAML files or directories. Directories are scanned
recursively for `.json`, `.yaml`, and `.yml` files.

Output formats:

| Format | Use |
| --- | --- |
| `json` | Machine-readable findings |
| `markdown` | Pull-request comments or local reports |
| `sarif` | Code scanning integrations |

`--fail-on` returns exit code `2` when a finding meets or exceeds the configured
severity.

## List Rules

```bash
clusterguard rules
clusterguard rules --format json
```

## Create a Policy File

```bash
clusterguard config init --output clusterguard-policy.yaml
```
