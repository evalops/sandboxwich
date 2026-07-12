#!/usr/bin/env python3
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RecoveryConformanceContract(unittest.TestCase):
    def test_live_script_covers_destructive_recovery(self) -> None:
        script = (ROOT / "deploy/kubernetes/kind-conformance.sh").read_text()
        for marker in (
            "api-restart-recovered",
            "worker-restart-recovered",
            "lease-loss-recovered",
            "out-of-band-pod-deletion",
            "idempotent-cleanup-recovered",
        ):
            self.assertIn(marker, script)


if __name__ == "__main__":
    unittest.main()
