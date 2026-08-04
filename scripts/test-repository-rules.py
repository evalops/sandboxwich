#!/usr/bin/env python3
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class RepositoryRulesTest(unittest.TestCase):
    def test_ruleset_requires_stable_pull_request_checks(self) -> None:
        ruleset = json.loads((ROOT / ".github/rulesets/main.json").read_text())
        status_rule = next(
            rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks"
        )
        contexts = {
            check["context"]
            for check in status_rule["parameters"]["required_status_checks"]
        }
        self.assertEqual(
            contexts,
            {
                "rust",
                "clippy",
                "audit",
                "msrv (1.95)",
                "service image (sandboxwich-api)",
                "service image (sandboxwich-worker)",
                "runtime image (ubuntu-dev)",
            },
        )

    def test_pr_workflows_run_for_every_pull_request(self) -> None:
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/containers.yml",
        ):
            text = (ROOT / relative).read_text()
            pull_request = text.split("pull_request:", 1)[1].split("push:", 1)[0]
            self.assertNotIn("paths:", pull_request, relative)

    def test_protected_workflows_cancel_superseded_runs(self) -> None:
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/containers.yml",
            ".github/workflows/kubernetes-conformance.yml",
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("concurrency:", text, relative)
            self.assertIn("cancel-in-progress: true", text, relative)
            self.assertIn("github.event.pull_request.number || github.ref", text, relative)

    def test_kubernetes_conformance_runs_after_merge(self) -> None:
        workflow = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        triggers = workflow.split("permissions:", 1)[0]
        self.assertNotIn("pull_request:", triggers)
        self.assertIn("push:", triggers)
        self.assertIn("branches: [main]", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        self.assertIn("kind:", workflow)

    def test_ruleset_requires_pull_requests_and_blocks_force_pushes(self) -> None:
        ruleset = json.loads((ROOT / ".github/rulesets/main.json").read_text())
        types = {rule["type"] for rule in ruleset["rules"]}
        self.assertIn("pull_request", types)
        self.assertIn("non_fast_forward", types)
        self.assertIn("deletion", types)

    def test_container_builds_use_native_architecture_runners(self) -> None:
        workflow = (ROOT / ".github/workflows/containers.yml").read_text()
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn("docker buildx imagetools create", workflow)
        self.assertIn("linux/amd64", workflow)
        self.assertIn("linux/arm64", workflow)
        self.assertNotIn("qemu", workflow.lower())
        self.assertNotIn("binfmt", workflow.lower())
        self.assertIn("name: service image (${{ matrix.bin }})", workflow)
        self.assertIn("name: runtime image (ubuntu-dev)", workflow)

    def test_container_workflow_verifies_and_signs_platform_provenance(self) -> None:
        workflow = (ROOT / ".github/workflows/containers.yml").read_text()
        verifier = (ROOT / "scripts/verify-image-provenance.sh").read_text()
        for marker in (
            "dev.sandboxwich.build.runner-architecture",
            "dev.sandboxwich.build.dockerfile-digest",
            "dev.sandboxwich.build.dependency-lock-digest",
            "verify-image-provenance.sh",
            "Sign service platform manifests",
            "Sign runtime platform manifests",
            "provenance-summary.json",
        ):
            self.assertIn(marker, workflow)
        self.assertEqual(workflow.count("provenance: mode=max,version=v1"), 2)
        for marker in (
            "{{json .Provenance}}",
            "{{json .SBOM}}",
            "linux/amd64",
            "linux/arm64",
            "attestation-manifest",
            "cosign verify",
        ):
            self.assertIn(marker, verifier)
        self.assertNotIn("qemu", workflow.lower())
        self.assertNotIn("binfmt", workflow.lower())


if __name__ == "__main__":
    unittest.main()
