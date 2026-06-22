import tempfile
import unittest
from pathlib import Path

from clusterguard import load_resources, scan_resource, scan_resources
from clusterguard.cli import run
from clusterguard.policy import apply_policy, load_policy
from clusterguard.registry import RULES
from clusterguard.reports import findings_to_markdown, findings_to_sarif, rules_to_markdown
from clusterguard.scanner import collect_manifest_paths, scan_paths


class ClusterGuardTests(unittest.TestCase):
    def test_flags_exposed_services(self) -> None:
        service = {
            "kind": "Service",
            "metadata": {"name": "ray-head", "namespace": "ml"},
            "spec": {"type": "LoadBalancer"},
        }

        findings = scan_resource(service)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CG003")
        self.assertIn("LoadBalancer", findings[0].message)

    def test_flags_workload_security_and_resource_risks(self) -> None:
        deployment = {
            "kind": "Deployment",
            "metadata": {"name": "trainer", "namespace": "ml"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [
                            {
                                "name": "worker",
                                "image": "trainer:latest",
                                "securityContext": {"privileged": True},
                                "resources": {"requests": {"cpu": "1"}},
                            }
                        ],
                    }
                }
            },
        }

        findings = scan_resource(deployment)
        rule_ids = [finding.rule_id for finding in findings]

        self.assertEqual(rule_ids.count("CG002"), 2)
        self.assertIn("CG001", rule_ids)
        self.assertIn("CG004", rule_ids)
        self.assertIn("CG006", rule_ids)
        self.assertIn("CG008", rule_ids)

    def test_clean_workload_has_no_findings(self) -> None:
        pod = {
            "kind": "Pod",
            "metadata": {"name": "preprocessor"},
            "spec": {
                "containers": [
                    {
                        "name": "main",
                        "image": "preprocessor:1.2.3",
                        "securityContext": {"runAsNonRoot": True},
                        "resources": {
                            "requests": {"cpu": "1", "memory": "2Gi"},
                            "limits": {"cpu": "2", "memory": "4Gi"},
                        },
                        "readinessProbe": {"exec": {"command": ["true"]}},
                    }
                ]
            },
        }

        self.assertEqual(scan_resource(pod), [])

    def test_loads_multi_document_yaml_and_scans_all_resources(self) -> None:
        manifest = """
apiVersion: v1
kind: Service
metadata:
  name: notebook
spec:
  type: NodePort
---
apiVersion: v1
kind: Pod
metadata:
  name: trainer
spec:
  containers:
    - name: main
      image: trainer:latest
      resources:
        requests:
          cpu: "1"
          memory: 1Gi
        limits:
          cpu: "2"
          memory: 2Gi
      securityContext:
        runAsNonRoot: true
      readinessProbe:
        httpGet:
          path: /healthz
          port: 8080
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.yaml"
            path.write_text(manifest, encoding="utf-8")

            resources = load_resources(path)
            findings = scan_resources(resources)

        self.assertEqual(len(resources), 2)
        self.assertEqual([finding.rule_id for finding in findings], ["CG003", "CG004"])

    def test_sarif_report_contains_rules_and_results(self) -> None:
        service = {
            "kind": "Service",
            "metadata": {"name": "public"},
            "spec": {"type": "NodePort"},
        }

        report = findings_to_sarif(scan_resource(service))

        self.assertIn('"version": "2.1.0"', report)
        self.assertIn('"ruleId": "CG003"', report)

    def test_scans_directories_and_adds_source_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest = root / "service.yaml"
            manifest.write_text(
                """
apiVersion: v1
kind: Service
metadata:
  name: public
spec:
  type: NodePort
""",
                encoding="utf-8",
            )
            ignored = root / "notes.txt"
            ignored.write_text("not a manifest\n", encoding="utf-8")

            paths = collect_manifest_paths([root])
            findings = scan_paths([root])

        self.assertEqual([path.name for path in paths], ["service.yaml"])
        self.assertEqual(findings[0].source, str(manifest))
        self.assertEqual(findings[0].to_dict()["source"], str(manifest))

    def test_markdown_reports_include_source_column(self) -> None:
        service = {
            "kind": "Service",
            "metadata": {"name": "public"},
            "spec": {"type": "NodePort"},
        }
        report = findings_to_markdown(scan_resource(service))

        self.assertIn(
            "| Severity | Rule | Category | Source | Resource | Finding | Remediation |",
            report,
        )

    def test_rules_catalog_renders_for_cli_docs(self) -> None:
        report = rules_to_markdown(RULES)

        self.assertIn("CG001", report)
        self.assertIn("Missing resource requests or limits", report)

    def test_policy_suppresses_and_overrides_findings(self) -> None:
        service = {
            "kind": "Service",
            "metadata": {"name": "public", "namespace": "ml"},
            "spec": {"type": "NodePort"},
        }
        pod = {
            "kind": "Pod",
            "metadata": {"name": "trainer", "namespace": "ml"},
            "spec": {
                "containers": [
                    {
                        "name": "main",
                        "image": "trainer:latest",
                        "securityContext": {"runAsNonRoot": True},
                        "resources": {
                            "requests": {"cpu": "1", "memory": "1Gi"},
                            "limits": {"cpu": "1", "memory": "1Gi"},
                        },
                    }
                ]
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text(
                """
severity_overrides:
  CG008: medium
suppressions:
  - rule_id: CG003
    resource: Service/ml/public
""",
                encoding="utf-8",
            )

            findings = apply_policy(scan_resources([service, pod]), load_policy(policy_path))

        rule_ids = [finding.rule_id for finding in findings]
        self.assertNotIn("CG003", rule_ids)
        self.assertEqual(findings[-1].rule_id, "CG008")
        self.assertEqual(findings[-1].severity, "medium")

    def test_cli_config_init_writes_starter_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "policy.yaml"

            status = run(["config", "init", "--output", str(output)])

            self.assertEqual(status, 0)
            self.assertIn("disabled_rules", output.read_text(encoding="utf-8"))

    def test_cli_rules_command_runs(self) -> None:
        self.assertEqual(run(["rules", "--format", "json"]), 0)


if __name__ == "__main__":
    unittest.main()
