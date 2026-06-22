# Rule Catalog

Kube ClusterGuard rules are deterministic static checks. Each finding includes a
rule ID, severity, category, resource, message, and remediation.

| Rule | Severity | Category | Rationale |
| --- | --- | --- | --- |
| CG001 | medium | resource-governance | Missing requests or limits weaken scheduling, capacity planning, and cost control. |
| CG002 | high | pod-security | Privileged mode and host namespaces expand the blast radius of compromised workloads. |
| CG003 | medium | network-exposure | `LoadBalancer` and `NodePort` services should receive explicit exposure review. |
| CG004 | medium | supply-chain | Mutable or implicit image tags reduce rollout reproducibility. |
| CG005 | medium | identity | Service account tokens should not be mounted unless workloads need API access. |
| CG006 | medium/high | pod-security | Root execution and privilege escalation conflict with least-privilege defaults. |
| CG007 | medium | gpu-governance | GPU limits without matching requests make scheduling intent ambiguous. |
| CG008 | low | reliability | Long-running services should expose readiness or liveness signals. |

## Policy Configuration

Policy files may be JSON or YAML:

```yaml
disabled_rules:
  - CG008
severity_overrides:
  CG003: high
suppressions:
  - rule_id: CG003
    resource: Service/ml/notebook
    reason: "Reviewed temporary exposure for a private test cluster."
```

Suppression resources use shell-style wildcard matching, so
`Deployment/ml/*/trainer` and `*/ml/notebook` are valid patterns.
