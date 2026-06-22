# Configuration

Policy files are optional JSON or YAML documents.

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

## Disabled Rules

Use `disabled_rules` sparingly. It removes matching findings from all reports.

## Severity Overrides

Use `severity_overrides` when your organization wants to enforce a rule at a
different level than the default.

## Suppressions

Suppressions match by `rule_id` and `resource`. Both fields support shell-style
wildcards. Suppressions should include a reason so accepted risk is clear during
review.

```yaml
suppressions:
  - rule_id: CG003
    resource: Service/ml/*
    reason: "Internal-only cluster network reviewed by platform team."
```
