#!/usr/bin/env python3
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE_RE = re.compile(r"^\s*image:\s*(ghcr\.io/evalops/sandboxwich-(?:api|worker))(@sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


class DeploymentImagesTest(unittest.TestCase):
    def test_runtime_pins_and_installs_orb_executor_toolchain(self) -> None:
        dockerfile = (ROOT / "deploy/runtime/ubuntu-dev/Dockerfile").read_text()
        self.assertRegex(
            dockerfile,
            r"ARG ORB_EXECUTOR_IMAGE=ghcr\.io/evalops/sandboxwich-orb-executor@sha256:[0-9a-f]{64}",
        )
        self.assertIn(
            "COPY --from=orb-executor /usr/local/bin/orb-executor /usr/local/bin/orb-executor",
            dockerfile,
        )
        self.assertIn(
            "COPY --from=orb-executor /usr/local/bin/codex /usr/local/bin/codex",
            dockerfile,
        )
        self.assertIn(
            "COPY --from=orb-executor /usr/local/bin/orb-deterministic-agent /usr/local/bin/orb-deterministic-agent",
            dockerfile,
        )
        self.assertIn(
            "COPY --from=orb-executor /opt/orb/agent-adapters.json /opt/orb/agent-adapters.json",
            dockerfile,
        )
        self.assertIn("ENV CODEX_HOME=/home/sandbox/.codex", dockerfile)
        self.assertIn(
            "ENV ORB_AGENT_ADAPTERS_FILE=/opt/orb/agent-adapters.json",
            dockerfile,
        )

    def test_runtime_pins_sccache_and_fixes_workspace_cache_environment(self) -> None:
        dockerfile = (ROOT / "deploy/runtime/ubuntu-dev/Dockerfile").read_text()
        self.assertIn("ARG SCCACHE_VERSION=v0.16.0", dockerfile)
        self.assertIn(
            "ARG SCCACHE_SHA256_AMD64=aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588",
            dockerfile,
        )
        self.assertIn(
            "ARG SCCACHE_SHA256_ARM64=f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784",
            dockerfile,
        )
        self.assertIn("amd64) sccache_arch=x86_64", dockerfile)
        self.assertIn("arm64) sccache_arch=aarch64", dockerfile)
        self.assertIn('sha256sum -c -', dockerfile)
        self.assertIn('sccache --version | grep -Fx "sccache 0.16.0"', dockerfile)
        for setting in (
            "RUSTC_WRAPPER=/usr/local/bin/sccache",
            "CARGO_INCREMENTAL=0",
            "SCCACHE_DIR=/workspace/.cache/sccache",
            "SCCACHE_BASEDIRS=/workspace",
            "SCCACHE_CACHE_SIZE=48M",
            "SCCACHE_IGNORE_SERVER_IO_ERROR=1",
        ):
            self.assertIn(f"ENV {setting}", dockerfile)

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
        api_text = (ROOT / "deploy/kubernetes/api.yaml").read_text()
        migration_text = (ROOT / "deploy/kubernetes/api-migrate.yaml").read_text()
        api_digests = [
            digest for image, digest in IMAGE_RE.findall(api_text) if image.endswith("-api")
        ]
        migration_digests = [
            digest
            for image, digest in IMAGE_RE.findall(migration_text)
            if image.endswith("-api")
        ]
        self.assertEqual(len(api_digests), 2)  # init container and API container
        self.assertEqual(len(migration_digests), 1)
        self.assertEqual(set(api_digests), set(migration_digests))

    def test_migration_job_is_versioned_and_gates_api_rollout(self) -> None:
        migration_text = (ROOT / "deploy/kubernetes/api-migrate.yaml").read_text()
        api_text = (ROOT / "deploy/kubernetes/api.yaml").read_text()
        rollout_script = (ROOT / "deploy/kubernetes/apply-api.sh").read_text()

        job_name = re.search(r"name: sandboxwich-api-migrate-([0-9a-f]{12})$", migration_text, re.MULTILINE)
        digest = re.search(r"sandboxwich-api@sha256:([0-9a-f]{64})", migration_text)
        self.assertIsNotNone(job_name)
        self.assertIsNotNone(digest)
        assert job_name is not None and digest is not None
        self.assertEqual(job_name.group(1), digest.group(1)[:12])
        self.assertNotIn("kind: Job", api_text)
        self.assertIn("name: check-schema", api_text)
        self.assertIn("- check-schema", api_text)
        self.assertIn('value: "false"', api_text)

        migration_apply = rollout_script.index('apply -f "${ROOT_DIR}/api-migrate.yaml"')
        migration_wait = rollout_script.index("wait --for=condition=complete")
        deployment_apply = rollout_script.index('apply -f "${ROOT_DIR}/api.yaml"')
        self.assertLess(migration_apply, migration_wait)
        self.assertLess(migration_wait, deployment_apply)
        scale_down = rollout_script.index("scale deployment/sandboxwich-api --replicas=0")
        api_rollout = rollout_script.index(
            "rollout status deployment/sandboxwich-api", deployment_apply
        )
        worker_apply = rollout_script.index('apply -f "${ROOT_DIR}/worker.yaml"')
        self.assertLess(scale_down, migration_apply)
        self.assertLess(deployment_apply, api_rollout)
        self.assertLess(api_rollout, worker_apply)

    def test_process_local_bootstrap_and_guest_ingress_are_deployable(self) -> None:
        api_text = (ROOT / "deploy/kubernetes/api.yaml").read_text()
        self.assertRegex(api_text, r"(?m)^  replicas: 1$")
        self.assertIn("type: Recreate", api_text)
        self.assertIn("kubernetes.io/metadata.name: sandboxwich-sandboxes", api_text)
        self.assertIn("port: 3217", api_text)

    def test_worker_enables_fenced_orphan_cleanup(self) -> None:
        worker_text = (ROOT / "deploy/kubernetes/worker.yaml").read_text()
        self.assertEqual(worker_text.count("- --orphan-reconciliation-apply"), 1)
        self.assertEqual(
            worker_text.count("name: SANDBOXWICH_ORPHAN_RECONCILIATION_APPLY"), 1
        )
        self.assertIn('value: "1"', worker_text)
        self.assertIn(
            "value: http://sandboxwich-api.sandboxwich.svc:3217", worker_text
        )

        conformance = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        self.assertNotIn("kubectl -n sandboxwich set env", conformance)
        self.assertNotIn(
            '"value":"--orphan-reconciliation-apply"', conformance
        )

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

    def test_kind_runtime_placement_proof_uses_the_published_digest(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        workflow = (ROOT / ".github/workflows/kubernetes-conformance.yml").read_text()
        self.assertIn(
            'SANDBOXWICH_RUNTIME_IMAGE must be digest-pinned', script
        )
        self.assertIn(
            'docker exec "${node}" crictl pull "${runtime_image}"', workflow
        )
        self.assertIn(
            'echo "SANDBOXWICH_RUNTIME_IMAGE=${runtime_image}"',
            workflow,
        )
        self.assertIn(
            'echo "SANDBOXWICH_WORKER_IMAGE=${gateway_image}"',
            workflow,
        )
        self.assertIn(
            'echo "SANDBOXWICH_API_IMAGE=${api_image}"', workflow
        )
        self.assertIn(
            'echo "SANDBOXWICH_POSTGRES_IMAGE=${postgres_image}"', workflow
        )
        self.assertIn(
            'docker image rm -f sandboxwich-runtime:conformance', workflow
        )
        self.assertNotIn("kind load docker-image", script)

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

    def test_gateway_registry_is_enabled_and_preflighted_on_every_kind_node(self) -> None:
        cluster = (ROOT / "deploy/kubernetes/kind-conformance.yaml").read_text()
        workflow = (ROOT / ".github/workflows/kubernetes-conformance.yml").read_text()
        self.assertIn('config_path = "/etc/containerd/certs.d"', cluster)
        self.assertIn('crictl pull "${gateway_image}"', workflow)


if __name__ == "__main__":
    unittest.main()
