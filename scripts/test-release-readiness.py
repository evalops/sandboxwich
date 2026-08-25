#!/usr/bin/env python3
import pathlib
import re
import subprocess
import tomllib
import unittest

import yaml


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

    def test_release_workflow_is_retired(self) -> None:
        self.assertFalse((ROOT / ".github/workflows/release.yml").exists())

    def test_release_no_longer_has_mutating_permissions(self) -> None:
        workflows = "\n".join(
            path.read_text() for path in (ROOT / ".github/workflows").glob("*.yml")
        )
        self.assertNotIn("contents: write", workflows)
        self.assertNotIn("packages: write", workflows)
        self.assertNotIn("id-token: write", workflows)
        self.assertNotIn("attestations: write", workflows)

    def test_all_workflow_files_parse_as_yaml(self) -> None:
        # A workflow file that does not parse only fails when it next runs,
        # which is how an invalid release workflow once shipped to main.
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for path in workflows:
            with path.open() as fh:
                yaml.safe_load(fh)

    def test_cargo_release_machinery_removed(self) -> None:
        # The compatibility snapshot must not regain an independent release
        # workflow, cargo-release workflow, or tag-after-merge hook.
        self.assertFalse((ROOT / ".github/workflows/bump-version.yml").exists())
        self.assertFalse((ROOT / ".github/workflows/tag-release.yml").exists())
        self.assertFalse((ROOT / "scripts/bump-changelog.sh").exists())
        self.assertNotIn("workspace.metadata.release]", (ROOT / "Cargo.toml").read_text())

    def test_release_plz_workflow_is_retired_and_config_is_historical(self) -> None:
        self.assertFalse((ROOT / ".github/workflows/release-plz.yml").exists())

        with (ROOT / "release-plz.toml").open("rb") as fh:
            config = tomllib.load(fh)
        workspace = config["workspace"]
        # Unpublished crates: git tags are the release source of truth.
        self.assertTrue(workspace["git_only"])
        self.assertFalse(workspace["publish"])
        # release.yml owns the GitHub release; release-plz only tags.
        self.assertFalse(workspace["git_release_enable"])
        self.assertEqual(workspace["git_tag_name"], "v{{ version }}")
        owners = [
            package["name"]
            for package in config.get("package", [])
            if package.get("changelog_path") == "CHANGELOG.md"
        ]
        self.assertEqual(owners, ["sandboxwich-core"])

    def test_workspace_crates_share_one_version(self) -> None:
        # Lockstep versioning is what makes the single vX.Y.Z tag and the
        # release.yml artifact naming coherent; every crate must inherit.
        root = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertIn("version", root["workspace"]["package"])
        for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
            crate = tomllib.loads(manifest.read_text())
            self.assertEqual(
                crate["package"]["version"], {"workspace": True}, str(manifest)
            )

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
