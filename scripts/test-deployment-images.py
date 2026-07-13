#!/usr/bin/env python3
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE_RE = re.compile(r"^\s*image:\s*(ghcr\.io/evalops/sandboxwich-(?:api|worker))(@sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


class DeploymentImagesTest(unittest.TestCase):
    def test_service_images_are_pinned_to_oci_digests(self) -> None:
        documents = {
            path: path.read_text()
            for path in (ROOT / "deploy/kubernetes").glob("*.yaml")
        }
        tagged = [
            line.strip()
            for text in documents.values()
            for line in text.splitlines()
            if "image: ghcr.io/evalops/sandboxwich-" in line
            and not IMAGE_RE.match(line)
        ]
        self.assertEqual(tagged, [])

    def test_migration_and_api_use_the_same_api_digest(self) -> None:
        text = (ROOT / "deploy/kubernetes/api.yaml").read_text()
        api_digests = [digest for image, digest in IMAGE_RE.findall(text) if image.endswith("-api")]
        self.assertEqual(len(api_digests), 2)
        self.assertEqual(len(set(api_digests)), 1)

    def test_kind_conformance_rewrites_pinned_images_to_local_builds(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        self.assertIn("sandboxwich-api@sha256:[0-9a-f]\\{64\\}", script)
        self.assertIn("sandboxwich-worker@sha256:[0-9a-f]\\{64\\}", script)

    def test_kind_enables_containerd_registry_host_rewrites(self) -> None:
        config = (ROOT / "deploy/kubernetes/kind-conformance.yaml").read_text()
        workflow = (ROOT / ".github/workflows/kubernetes-conformance.yml").read_text()
        self.assertIn("containerdConfigPatches:", config)
        self.assertIn('config_path = "/etc/containerd/certs.d"', config)
        self.assertIn(
            'docker exec "${node}" crictl pull "${gateway_image}"', workflow
        )

    def test_private_dns_probe_cannot_bypass_the_gateway_via_no_proxy(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        self.assertIn(
            'curl --noproxy "" -fsS --max-time 5 http://localhost/',
            script,
        )

    def test_gateway_outage_probe_bypasses_the_proxy(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        self.assertIn(
            'curl --noproxy \\"*\\" -fsS --max-time 5 http://example.com/',
            script,
        )

    def test_negative_probes_accept_failed_command_status(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        self.assertIn(
            '[[ "${status}" == "finished" || "${status}" == "failed" ]] && return 0',
            script,
        )
        self.assertIn(
            'wait_command_terminal "http://127.0.0.1:32170/commands/${command_id}"',
            script,
        )
        self.assertIn("assert_command_failed_with_exit", script)
        self.assertIn(".command.exit_code != null", script)


if __name__ == "__main__":
    unittest.main()
