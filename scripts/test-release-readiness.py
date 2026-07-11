#!/usr/bin/env python3
import pathlib
import re
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


if __name__ == "__main__":
    unittest.main()
