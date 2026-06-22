# Validation Notes

Validation for the `0.1.0` release focuses on deterministic behavior that can be
reproduced without cluster access.

## Automated Checks

- Unit tests cover service exposure, pod-security risks, clean workloads,
  directory scanning, source attribution, multi-document YAML loading, SARIF
  report generation, rule catalog rendering, config generation, and policy
  filtering.
- CLI smoke checks cover version output, diagnostics, rule listing, and manifest
  scanning.
- Ruff linting is clean.
- Source distribution and wheel builds complete successfully.

## Example Scenario

`examples/risky-deployment.yaml` models a GPU training deployment with public
service exposure, host networking, privileged runtime, mutable image tags,
service account token automounting, a GPU limit without a matching request, and
missing probes.

Run:

```bash
clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown
clusterguard scan examples/clean-deployment.yaml --fail-on low
clusterguard rules --format markdown
```

The expected report contains high-, medium-, and low-severity findings that map
directly to the rule catalog in `docs/rules.md`.
