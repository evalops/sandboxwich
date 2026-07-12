#!/usr/bin/env python3
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CiliumConformanceContract(unittest.TestCase):
    def test_workflow_runs_live_cilium_fqdn_proof(self) -> None:
        workflow = (ROOT / ".github/workflows/kubernetes-conformance.yml").read_text()
        self.assertIn("cilium-fqdn", workflow)
        self.assertIn("kind-cilium.yaml", workflow)
        self.assertIn("cilium-fqdn-conformance.sh", workflow)
        self.assertIn("cilium/cilium", workflow)

    def test_proof_covers_required_network_cases(self) -> None:
        script = (ROOT / "deploy/kubernetes/cilium-fqdn-conformance.sh").read_text()
        for marker in (
            "allowed-fqdn",
            "denied-fqdn",
            "dns-failure",
            "redirect-chain",
            "metadata-denied",
            "apiserver-denied",
            "ipv4-allowed",
            "ipv6-denied",
        ):
            self.assertIn(marker, script)

    def test_kind_cluster_disables_default_cni(self) -> None:
        config = (ROOT / "deploy/kubernetes/kind-cilium.yaml").read_text()
        self.assertIn("disableDefaultCNI: true", config)


if __name__ == "__main__":
    unittest.main()
