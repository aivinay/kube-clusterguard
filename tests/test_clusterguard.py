import unittest

from clusterguard import scan_resource


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

    def test_clean_workload_has_no_findings(self) -> None:
        pod = {
            "kind": "Pod",
            "metadata": {"name": "preprocessor"},
            "spec": {
                "containers": [
                    {
                        "name": "main",
                        "image": "preprocessor:1.2.3",
                        "resources": {
                            "requests": {"cpu": "1", "memory": "2Gi"},
                            "limits": {"cpu": "2", "memory": "4Gi"},
                        },
                    }
                ]
            },
        }

        self.assertEqual(scan_resource(pod), [])


if __name__ == "__main__":
    unittest.main()
