#!/usr/bin/env python3
import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseReadinessTest(unittest.TestCase):
    def test_roadmap_has_objective_promotion_gates(self) -> None:
        roadmap = (ROOT / "ROADMAP.md").read_text()
        for gate in (
            "Authorization",
            "Isolation",
            "Lifecycle recovery",
            "Conformance",
            "Telemetry",
            "Documentation",
        ):
            self.assertIn(f"### {gate}", roadmap)

    def test_changelog_declares_the_initial_release(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn("## 0.1.0 - 2026-07-11", changelog)

    def test_release_publishes_machine_contracts(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("sandboxwich-openapi.json", workflow)
        self.assertIn("sandboxwich-image-digests.txt", workflow)

    def test_bump_version_workflow_exists_and_is_gated(self) -> None:
        workflow = (ROOT / ".github/workflows/bump-version.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("cargo-release", workflow)
        self.assertIn("cargo release", workflow)
        self.assertIn("--no-publish", workflow)
        self.assertIn("--no-verify", workflow)
        self.assertIn("--no-push", workflow)
        self.assertIn("--no-tag", workflow)
        self.assertIn("gh pr create", workflow)

    def test_tag_release_workflow_follows_release_pr(self) -> None:
        workflow = (ROOT / ".github/workflows/tag-release.yml").read_text()
        self.assertIn("push:", workflow)
        self.assertIn("branches:", workflow)
        self.assertIn("- main", workflow)
        self.assertIn("chore(release): prepare for ", workflow)
        self.assertIn("git tag", workflow)
        self.assertIn("git push origin", workflow)

    def test_release_inventory_contains_every_pinned_service_image(self) -> None:
        manifests = "\n".join(
            path.read_text() for path in (ROOT / "deploy/kubernetes").glob("*.yaml")
        )
        released_images = set(
            re.findall(
                r"ghcr\.io/evalops/(sandboxwich-(?:api|worker|ubuntu-dev))@sha256:[0-9a-f]{64}",
                manifests,
            )
        )
        self.assertEqual(
            released_images,
            {"sandboxwich-api", "sandboxwich-worker", "sandboxwich-ubuntu-dev"},
        )

        inventory = subprocess.run(
            [str(ROOT / "scripts/release-image-digests.sh")],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertEqual(len(inventory), 3)
        self.assertEqual(
            {line.split("/")[-1].split("@")[0] for line in inventory},
            released_images,
        )


if __name__ == "__main__":
    unittest.main()
