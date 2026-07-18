#!/usr/bin/env python3
"""Example 2: snapshot a sandbox, then restore that snapshot into a new sandbox.

Prerequisites:
  - The sandboxwich API running locally (`cargo run -p sandboxwich-api -- serve`).
  - A dry-run worker running against the same API
    (`cargo run -p sandboxwich-worker -- run --name local-dry-run \\
       --provider kubernetes --provider-mode dry-run`).
    Dry-run mode simulates snapshot creation and fork restore without a real
    CSI VolumeSnapshotClass; see docs/capabilities.md ("Snapshots and forks")
    before relying on this against an apply-mode (real Kubernetes) worker.
  - SANDBOXWICH_API_TOKEN set to the same value in every shell.

Run:
  export SANDBOXWICH_API_TOKEN=local-development-token
  python3 examples/02_snapshot_fork.py
"""

from __future__ import annotations

import sys
import time

from sandboxwich import SandboxwichClient, SandboxwichError


def main() -> int:
    with SandboxwichClient("http://127.0.0.1:3217") as client:
        print("creating source sandbox...")
        created = client.create_sandbox(name="sdk-example-2-source")
        source = client.wait_for_sandbox_ready(created.sandbox.id, timeout=60.0)
        print(f"  source sandbox {source.id} is ready")

        print("creating a snapshot of it...")
        snapshot_response = client.create_snapshot(source.id, label="sdk-example-2")
        snapshot_id = snapshot_response.snapshot.id
        print(f"  snapshot {snapshot_id} queued (status={snapshot_response.snapshot.status.value})")

        # Snapshot lifecycle has no dedicated wait_for helper (it isn't part of
        # the sandbox/command state machines the CLI polls); poll get_snapshot
        # directly until it leaves Pending.
        snapshot = snapshot_response.snapshot
        deadline = time.monotonic() + 60.0
        while snapshot.status.value == "pending" and time.monotonic() < deadline:
            time.sleep(0.5)
            snapshot = client.get_snapshot(snapshot_id).snapshot
        print(f"  snapshot {snapshot_id} status={snapshot.status.value}")

        print("restoring the snapshot into a new sandbox...")
        restored = client.restore_snapshot(
            snapshot_id,
            template=source.template,
            memory_limit=source.memory_limit,
            name="sdk-example-2-restored",
        )
        child = client.wait_for_sandbox_ready(restored.sandbox.id, timeout=60.0)
        print(f"  restored sandbox {child.id} is ready (parent_snapshot_id={child.parent_snapshot_id})")

        print("also forking the still-live source sandbox directly...")
        forked = client.fork_sandbox(source.id, name="sdk-example-2-forked")
        fork_child = client.wait_for_sandbox_ready(forked.sandbox.id, timeout=60.0)
        print(f"  forked sandbox {fork_child.id} is ready")

        print("cleaning up...")
        for sandbox_id in (source.id, child.id, fork_child.id):
            client.stop_sandbox(sandbox_id)
        print("  done")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SandboxwichError as error:
        print(f"sandboxwich error: {error} (code={error.code}, status={error.status_code})", file=sys.stderr)
        sys.exit(1)
