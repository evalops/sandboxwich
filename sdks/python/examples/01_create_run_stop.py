#!/usr/bin/env python3
"""Example 1: create a sandbox, run a command, print its output, stop it.

Prerequisites:
  - The sandboxwich API running locally (`cargo run -p sandboxwich-api -- serve`).
  - A dry-run worker running against the same API
    (`cargo run -p sandboxwich-worker -- run --name local-dry-run \\
       --provider kubernetes --provider-mode dry-run`).
    Dry-run mode validates the control-plane flow without actually isolating
    or executing the command; see docs/capabilities.md before assuming this
    output reflects a real container's stdout.
  - SANDBOXWICH_API_TOKEN set to the same value in every shell (see the repo
    root README's Quick start).

Run:
  export SANDBOXWICH_API_TOKEN=local-development-token
  python3 examples/01_create_run_stop.py
"""

from __future__ import annotations

import sys

from sandboxwich import SandboxwichClient, SandboxwichError


def main() -> int:
    with SandboxwichClient("http://127.0.0.1:3217") as client:
        print("creating sandbox...")
        created = client.create_sandbox(name="sdk-example-1")
        print(f"  sandbox {created.sandbox.id} queued (state={created.sandbox.state.value})")

        print("waiting for it to become ready...")
        sandbox = client.wait_for_sandbox_ready(created.sandbox.id, timeout=60.0)
        print(f"  sandbox {sandbox.id} is ready")

        print("running `echo hello from sandboxwich`...")
        queued = client.run_command(sandbox.id, ["echo", "hello from sandboxwich"])
        command = client.wait_for_command(queued.command.id, timeout=60.0)

        print(f"  command finished with status={command.status.value} exit_code={command.exit_code}")
        print("  --- stdout ---")
        print(command.stdout, end="")
        if command.stderr:
            print("  --- stderr ---")
            print(command.stderr, end="")

        print("stopping sandbox...")
        stopped = client.stop_sandbox(sandbox.id)
        print(f"  sandbox {stopped.sandbox.id} is now {stopped.sandbox.state.value}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SandboxwichError as error:
        print(f"sandboxwich error: {error} (code={error.code}, status={error.status_code})", file=sys.stderr)
        sys.exit(1)
