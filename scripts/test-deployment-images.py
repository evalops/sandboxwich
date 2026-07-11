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


if __name__ == "__main__":
    unittest.main()
