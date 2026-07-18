#!/usr/bin/env python3
"""Example 3: agent-eval style command execution with live, ordered output streaming.

Runs a multi-line command and streams its `CommandOutputChunk`s as they
arrive, in `sequence` order, the way an agent harness would tail a running
tool call instead of waiting for it to finish.

Prerequisites:
  - The sandboxwich API running locally (`cargo run -p sandboxwich-api -- serve`).
  - A dry-run worker running against the same API
    (`cargo run -p sandboxwich-worker -- run --name local-dry-run \\
       --provider kubernetes --provider-mode dry-run`).
  - SANDBOXWICH_API_TOKEN set to the same value in every shell.

Run:
  export SANDBOXWICH_API_TOKEN=local-development-token
  python3 examples/03_stream_output.py
"""

from __future__ import annotations

import sys

from sandboxwich import CommandOutputStream, SandboxwichClient, SandboxwichError


def main() -> int:
    with SandboxwichClient("http://127.0.0.1:3217") as client:
        print("creating sandbox...")
        created = client.create_sandbox(name="sdk-example-3")
        sandbox = client.wait_for_sandbox_ready(created.sandbox.id, timeout=60.0)
        print(f"  sandbox {sandbox.id} is ready")

        print("running a multi-line command and streaming its output...")
        queued = client.run_command(
            sandbox.id,
            ["sh", "-c", "for i in 1 2 3; do echo \"line $i\"; done"],
        )

        last_sequence = -1
        for chunk in client.stream_command_output(queued.command.id, timeout=60.0):
            # The API guarantees ordering via `next_cursor`; this assertion is a
            # belt-and-suspenders check that `sequence` (what an agent harness
            # should key on to detect gaps/reordering, e.g. across a retry) never
            # goes backwards.
            assert chunk.sequence > last_sequence, (
                f"output chunk arrived out of order: sequence {chunk.sequence} "
                f"did not increase past {last_sequence}"
            )
            last_sequence = chunk.sequence
            stream = "stdout" if chunk.stream == CommandOutputStream.stdout else "stderr"
            print(f"  [seq={chunk.sequence} {stream}] {chunk.chunk!r}")

        command = client.wait_for_command(queued.command.id, timeout=60.0)
        print(f"command finished with status={command.status.value} exit_code={command.exit_code}")

        client.stop_sandbox(sandbox.id)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SandboxwichError as error:
        print(f"sandboxwich error: {error} (code={error.code}, status={error.status_code})", file=sys.stderr)
        sys.exit(1)
