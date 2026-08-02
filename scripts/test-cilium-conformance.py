#!/usr/bin/env python3
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/kubernetes/cilium-fqdn-conformance.sh"
WORKFLOW = ROOT / ".github/workflows/kubernetes-conformance.yml"


class CiliumConformanceContract(unittest.TestCase):
    def test_workflow_runs_live_cilium_fqdn_proof(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn("cilium-fqdn", workflow)
        self.assertIn("kind-cilium.yaml", workflow)
        self.assertIn("cilium-fqdn-conformance.sh", workflow)
        self.assertIn("cilium/cilium", workflow)

    def test_workflow_builds_the_worker_that_renders_the_policy(self) -> None:
        # The suite applies `render-egress-policy` output; without this build
        # it would silently fall back to compiling inside the timed job or
        # fail outright.
        self.assertIn("cargo build -p sandboxwich-worker", WORKFLOW.read_text())

    def test_workflow_enables_ipv6_so_the_ipv6_cases_are_real(self) -> None:
        self.assertIn("ipv6.enabled=true", WORKFLOW.read_text())

    def test_workflow_never_skips_the_ipv6_cases(self) -> None:
        self.assertNotIn("SANDBOXWICH_CONFORMANCE_SKIP_IPV6", WORKFLOW.read_text())

    def test_proof_covers_required_network_cases(self) -> None:
        script = SCRIPT.read_text()
        for marker in (
            "allowed-fqdn-ipv4",
            "allowed-fqdn-ipv6",
            "denied-fqdn-ipv4",
            "denied-fqdn-ipv6",
            "dns-failure",
            "redirect-chain",
            "metadata-denied",
            "apiserver-denied",
        ):
            self.assertIn(marker, script)

    def test_proof_applies_the_shipped_policy_rendering(self) -> None:
        # A hand-maintained copy of the policy would pass every case while the
        # rendering the control plane actually applies regressed.
        self.assertIn("render-egress-policy", SCRIPT.read_text())

    def test_proof_requires_the_l7_dns_rule_that_populates_the_fqdn_cache(
        self,
    ) -> None:
        # Cilium resolves `toFQDNs` only from DNS answers its proxy observes.
        self.assertIn('"dns" in port.get("rules", {})', SCRIPT.read_text())

    def test_kind_cluster_disables_default_cni(self) -> None:
        config = (ROOT / "deploy/kubernetes/kind-cilium.yaml").read_text()
        self.assertIn("disableDefaultCNI: true", config)

    def test_kind_cluster_is_dual_stack(self) -> None:
        config = (ROOT / "deploy/kubernetes/kind-cilium.yaml").read_text()
        self.assertIn("ipFamily: dual", config)


if __name__ == "__main__":
    unittest.main()
