# sandboxwich (Python SDK)

A small, handwritten, typed Python client for the [sandboxwich](../../README.md)
control plane. It wraps the same `/v1` HTTP surface as `sandboxwich-cli`
(`crates/sandboxwich-cli`) — sandbox lifecycle, command execution, files,
events, and snapshots — behind a synchronous `httpx`-based client with
pydantic v2 request/response models.

This is not a generated client. It covers the flows below; everything else
in the `~59`-path OpenAPI document (desktop sessions, SSH, workers, jobs,
leases, divergence, operator routes) is out of scope for now — use the CLI
or raw HTTP for those.

## Install

```sh
cd sdks/python
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python >= 3.10. Runtime dependencies are `httpx` and `pydantic` (v2)
only; `pytest` and `respx` are dev-only, for running the test suite below.

## Quickstart

Start the API and a dry-run worker (see the repo root
[README's Quick start](../../README.md#quick-start) for the full three-shell
walkthrough):

```sh
export SANDBOXWICH_API_TOKEN="local-development-token"
cargo run -p sandboxwich-api -- serve
# in another shell:
export SANDBOXWICH_API_TOKEN="local-development-token"
cargo run -p sandboxwich-worker -- run --name local-dry-run --provider kubernetes --provider-mode dry-run
```

Then, from Python:

```python
from sandboxwich import SandboxwichClient

with SandboxwichClient("http://127.0.0.1:3217") as client:
    created = client.create_sandbox(name="demo")
    sandbox = client.wait_for_sandbox_ready(created.sandbox.id)

    queued = client.run_command(sandbox.id, ["echo", "hello"])
    command = client.wait_for_command(queued.command.id)
    print(command.stdout, end="")

    client.stop_sandbox(sandbox.id)
```

See `examples/` for complete, runnable scripts.

## Auth

Pass a token explicitly or via the `SANDBOXWICH_API_TOKEN` environment
variable — the same variable the CLI and worker use:

```python
client = SandboxwichClient("http://127.0.0.1:3217", api_token="local-development-token")
# or: export SANDBOXWICH_API_TOKEN=... and omit api_token
client = SandboxwichClient("http://127.0.0.1:3217")
```

The token is sent only as an `Authorization: Bearer <token>` HTTP header. It
is never placed on a command line/argv and never logged by this SDK. For a
real multi-tenant deployment using `SANDBOXWICH_TENANT_TOKENS`, also pass
`tenant=` so the client's token is matched against the right tenant.

## Errors

Every non-2xx response uses the API's stable `{ "ok": false, "code",
"message" }` envelope. This SDK raises a `SandboxwichError` subclass with
`.status_code`, `.code`, and `.message` (via `str(exc)`) populated from it —
branch on `.code`, never on the message text, per the repo root README's
"Public API contract":

| Exception | HTTP status |
|---|---|
| `BadRequestError` | 400 |
| `UnauthorizedError` | 401, 403 |
| `NotFoundError` | 404 |
| `ConflictError` | 409 |
| `RateLimitedError` (has `.retry_after`) | 429 |
| `UnsupportedError` | 501 |
| `ServerError` | other 5xx |
| `SandboxwichConnectionError` / `SandboxwichTimeoutError` | transport failure (no response) |

## Capability caveats

sandboxwich is pre-1.0. Before relying on any of the below, read
[docs/capabilities.md](../../docs/capabilities.md) — the capability maturity
matrix is the actual product contract, not this README.

Notably, as reflected in this SDK:

- **`resume_sandbox` is unsupported today.** The route exists for CLI
  parity, but the API always returns a typed `501 unsupported`
  (`UnsupportedError`) — stop destroys the sandbox's resources, so create or
  fork a replacement instead.
- **Command execution and snapshots are Experimental.** In Kubernetes apply
  mode, command execution uses `kubectl exec` and snapshots require a working
  CSI `VolumeSnapshotClass`; a dry-run worker only simulates these paths.
  `run_command`/`create_snapshot` responses don't distinguish `dry_run` from
  `apply` themselves — that distinction lives in the worker's capability
  report — so don't treat a dry-run success as evidence that real isolated
  execution occurred.
- **Sandbox creation, stop, run_command, fork, and snapshot creation are all
  asynchronous.** Each returns HTTP 202 with an `Operation` alongside the
  primary resource; poll the resource itself (`get_sandbox`/`get_command`/
  `get_snapshot`) or use the provided `wait_for_*`/`stream_command_output`
  helpers rather than assuming completion from the initial response.

## Testing

```sh
cd sdks/python
source .venv/bin/activate
pytest
```

Tests use `respx` to mock `httpx` transport-level, covering request
serialization, response deserialization, and error-code-to-exception mapping
for the flows above — no network or live API required. See the top-level PR
description for whether an end-to-end run against a real local API (SQLite +
dry-run worker) was also performed.

## Layout

```
sdks/python/
  src/sandboxwich/
    client.py   # SandboxwichClient (sync, httpx.Client)
    models.py   # pydantic v2 request/response models
    errors.py   # SandboxwichError and subclasses
  examples/     # runnable end-to-end scripts
  tests/        # respx-mocked unit tests
```
