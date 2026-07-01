# Changelog

## 0.1.1 - 2026-07-01

- Hardened GitHub Actions permissions and Docker runtime user defaults.
- Added validation for policy severity overrides to avoid silently weakening
  CI gates.

## 0.1.0 - 2026-06-22

- Added JSON and YAML manifest loading, including Kubernetes `List` resources
  and multi-document YAML files.
- Added CI-oriented JSON, Markdown, and SARIF report formats.
- Added policy configuration for disabled rules, severity overrides, and
  explicit suppressions.
- Added source-file attribution, recursive directory scanning, CLI version,
  rule listing, diagnostics, starter policy generation, and release helper
  documentation.
- Expanded guardrail coverage for pod security, service account exposure, GPU
  request/limit consistency, mutable images, probes, and exposed services.
- Added GitHub Actions, contribution guidance, security policy, packaging
  metadata, Dockerfile, Makefile helpers, release-artifact workflow, and example
  risky/clean deployments.
