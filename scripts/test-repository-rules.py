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
                "buildkite/sandboxwich-ci",
                "service image (sandboxwich-api)",
                "service image (sandboxwich-worker)",
                "runtime image (ubuntu-dev)",
            },
        )

    def test_buildkite_rust_tests_are_postgres_backed(self) -> None:
        pipeline = (ROOT / ".buildkite/pipeline.yml").read_text()
        for marker in (
            "mirror.gcr.io/library/postgres:17@sha256:0af65001d05296a2ead57ac4a6412433d8913d1bb5d0c88435a7d1e1ee5cb04b",
            "pg_isready -U postgres -d sandboxwich",
            "docker port",
            "SANDBOXWICH_TEST_POSTGRES_URL",
            "cargo test --workspace --locked",
        ):
            self.assertIn(marker, pipeline)
        self.assertIn("docker rm -f", pipeline)

    def test_buildkite_heavy_jobs_use_all_connected_capacity(self) -> None:
        pipeline = (ROOT / ".buildkite/pipeline.yml").read_text()
        self.assertEqual(
            pipeline.count('concurrency_group: "hetzner-linux-heavy-workloads"'),
            2,
        )
        self.assertEqual(pipeline.count("concurrency: 3"), 2)

    def test_buildkite_retries_only_agent_loss_or_stop(self) -> None:
        pipeline = (ROOT / ".buildkite/pipeline.yml").read_text()
        self.assertEqual(pipeline.count("exit_status: -1"), 5)
        self.assertEqual(pipeline.count("signal_reason: none"), 5)
        self.assertEqual(pipeline.count("signal_reason: agent_stop"), 5)
        self.assertNotIn('exit_status: "*"', pipeline)

    def test_pr_workflows_run_for_every_pull_request(self) -> None:
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/containers.yml",
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("pull_request:", text, relative)
            self.assertNotIn("\n  push:", text, relative)
            self.assertNotIn("\n  workflow_dispatch:", text, relative)

    def test_protected_workflows_cancel_superseded_runs(self) -> None:
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/kubernetes-conformance.yml",
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("concurrency:", text, relative)
            self.assertIn("cancel-in-progress: true", text, relative)
            self.assertIn("github.event.pull_request.number || github.ref", text, relative)
        containers = (ROOT / ".github/workflows/containers.yml").read_text()
        self.assertIn("concurrency:", containers)
        self.assertIn("github.event.pull_request.number || github.ref", containers)
        self.assertIn("cancel-in-progress: true", containers)

    def test_kubernetes_conformance_runs_after_merge(self) -> None:
        workflow = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        triggers = workflow.split("permissions:", 1)[0]
        self.assertNotIn("pull_request:", triggers)
        self.assertNotIn("push:", triggers)
        self.assertNotIn("workflow_run:", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        self.assertIn("kind:", workflow)

    def test_kubernetes_conformance_pulls_the_published_container_paths(self) -> None:
        containers = (ROOT / ".github/workflows/containers.yml").read_text()
        conformance = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        self.assertIn("REGISTRY: ghcr.io", containers)
        self.assertIn("IMAGE_NAMESPACE: evalops", containers)
        self.assertIn("REGISTRY: ghcr.io", conformance)
        self.assertIn("IMAGE_NAMESPACE: evalops", conformance)
        for image in (
            "sandboxwich-api",
            "sandboxwich-worker",
            "sandboxwich-ubuntu-dev",
        ):
            published_ref = (
                "${REGISTRY}/${IMAGE_NAMESPACE}/"
                f"{image}:sha-${{short_sha}}"
            )
            self.assertIn(published_ref, conformance)
        self.assertNotIn("ghcr.io/evalops/sandboxwich/", conformance)

    def test_kubernetes_conformance_pins_kind_images_to_local_registry(self) -> None:
        # kind nodes have no GHCR credentials. RepoDigests after a private
        # GHCR pull still lists ghcr.io first; head -n1 would make crictl
        # pull that digest and 401. The workflow must select localhost:5001.
        conformance = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        self.assertIn("local_repo_digest()", conformance)
        self.assertIn('grep -F "${prefix}@"', conformance)
        self.assertIn(
            '[[ "${digest}" == "${prefix}"@sha256:* ]]',
            conformance,
        )
        # No unfiltered RepoDigests | head -n1 selection remains.
        self.assertNotRegex(
            conformance,
            r"RepoDigests\}\{\{println \.\}\}\{\{end\}\}' \| head -n1",
        )

    def test_kubernetes_conformance_retries_pinned_kind_downloads(self) -> None:
        conformance = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        download = (
            "curl --retry 5 --retry-all-errors --retry-delay 2 -fsSLo kind"
        )
        direct_release = (
            "https://github.com/kubernetes-sigs/kind/releases/download/"
            "v0.29.0/kind-linux-amd64"
        )
        checksum = (
            "c72eda46430f065fb45c5f70e7c957cc9209402ef309294821978677c8fb3284"
        )
        self.assertEqual(conformance.count(download), 2)
        self.assertEqual(conformance.count(direct_release), 2)
        self.assertEqual(conformance.count(checksum), 2)
        self.assertNotIn("https://kind.sigs.k8s.io/dl/", conformance)

    def test_kubernetes_conformance_diagnostics_tolerate_missing_clusters(self) -> None:
        conformance = (
            ROOT / ".github/workflows/kubernetes-conformance.yml"
        ).read_text()
        for cluster in ("sandboxwich-conformance", "sandboxwich-cilium"):
            self.assertIn(
                f"kind get clusters | grep -Fxq {cluster}",
                conformance,
            )
        self.assertIn("kubectl get all -A -o wide || true", conformance)
        self.assertIn("kubectl get nodes,pods -A -o wide || true", conformance)

    def test_release_plz_tags_only_sandboxwich_core(self) -> None:
        # Shared vX.Y.Z tags must be created once. Releasing every workspace
        # package tries a second create and fails with Reference already exists.
        config = (ROOT / "release-plz.toml").read_text()
        self.assertIn('name = "sandboxwich-core"', config)
        for package in (
            "sandboxwich-agent",
            "sandboxwich-api",
            "sandboxwich-bench",
            "sandboxwich-cli",
            "sandboxwich-worker",
        ):
            self.assertRegex(
                config,
                rf'name = "{package}"\s*\nrelease = false',
            )

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
        self.assertEqual(workflow.count("push: false"), 2)
        self.assertEqual(workflow.count("provenance: false"), 2)
        self.assertEqual(workflow.count("sbom: false"), 2)
        self.assertNotIn("packages: write", workflow)
        self.assertNotIn("id-token: write", workflow)
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

    def test_expensive_pr_jobs_are_scoped_and_benchmark_is_post_merge_only(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        containers = (ROOT / ".github/workflows/containers.yml").read_text()
        self.assertIn("name: ci scope", ci)
        self.assertIn("name: container scope", containers)
        self.assertIn("if: github.event_name != 'pull_request'", ci)

    def test_mono_is_the_only_release_and_publication_authority(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("evalops/mono", readme)
        self.assertIn("must not publish artifacts", readme)
        for relative in (
            ".github/workflows/release-plz.yml",
            ".github/workflows/release.yml",
        ):
            workflow = (ROOT / relative).read_text()
            self.assertIn("retired", workflow.lower(), relative)
            self.assertIn("workflow_dispatch:", workflow, relative)
            self.assertIn("exit 1", workflow, relative)
            self.assertNotIn("contents: write", workflow, relative)
            self.assertNotIn("id-token: write", workflow, relative)
        self.assertNotIn("release-plz/action@", (ROOT / ".github/workflows/release-plz.yml").read_text())
        self.assertNotIn("softprops/action-gh-release@", (ROOT / ".github/workflows/release.yml").read_text())


if __name__ == "__main__":
    unittest.main()
