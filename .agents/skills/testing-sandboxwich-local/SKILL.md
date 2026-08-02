---
name: testing-sandboxwich-local
description: Run sandboxwich-api plus a dry-run worker locally and drive sandbox lifecycle flows (create/snapshot/stop/resume/fork) end-to-end through the CLI for manual or agentic testing.
---

# Local end-to-end testing of sandboxwich

Use this when you need a real running control plane (not unit tests) to exercise
sandbox lifecycle behavior: provision, snapshot, stop, resume, fork, jobs.

## Build

```sh
cargo build -p sandboxwich-api -p sandboxwich-worker -p sandboxwich-cli
```

The CLI binary is `target/debug/sandboxwich` (NOT `sandboxwich-cli`); the crate
name and the binary name differ, which is easy to trip over when invoking the
built binary directly instead of `cargo run -p sandboxwich-cli --`.

## Start the API

Prefer a scratch directory so you get a clean SQLite database per run:

```sh
mkdir -p /tmp/sbwtest && cd /tmp/sbwtest && rm -f test.db*
SANDBOXWICH_TENANT_TOKENS="acme=acme-token,globex=globex-token" \
SANDBOXWICH_DATABASE_URL="sqlite:///tmp/sbwtest/test.db?mode=rwc" \
  target/debug/sandboxwich-api serve
```

Use `SANDBOXWICH_TENANT_TOKENS` (not `SANDBOXWICH_API_TOKEN`) whenever the test
involves cross-tenant isolation: with a single shared token every request is
forced onto `SANDBOXWICH_DEFAULT_TENANT` and a client-supplied
`x-sandboxwich-tenant` header is ignored, so a "cross-tenant" test would be
meaningless. Tenant identity comes only from which bearer token matched.

## Start a dry-run worker (gotchas)

```sh
SANDBOXWICH_API_TOKEN=acme-token \
SANDBOXWICH_RUNTIME_IMAGE="ghcr.io/evalops/sandboxwich-runtime@sha256:<64 hex chars>" \
setsid nohup target/debug/sandboxwich-worker run \
  --name local-dry-run --provider kubernetes --provider-mode dry-run \
  > worker.log 2>&1 < /dev/null &
```

- The worker reads its bearer token from the `SANDBOXWICH_API_TOKEN` env var;
  there is no `--api-token` argument on the `run` subcommand.
- `SANDBOXWICH_RUNTIME_IMAGE` **must** be pinned by sha256 digest even in
  dry-run mode. Without it, `POST /v1/sandboxes` fails with
  `500 {"code":"internal","message":"worker placement runtime image is not
  digest-pinned"}`. Any syntactically valid `@sha256:<64 hex>` reference works
  in dry-run; the image is never pulled.
- Start the worker with `setsid`/`disown` from agent shells. A plain background
  job gets a shutdown signal when the spawning shell exits and the worker logs
  "shutdown requested, exiting work loop", which then looks like jobs silently
  never being claimed.

## Golden lifecycle through the CLI

```sh
export SANDBOXWICH_API_TOKEN=acme-token   # or globex-token for the other tenant
CLI=target/debug/sandboxwich
$CLI new --name demo --memory-limit 4g --wait      # workspace_mode defaults to persistent
$CLI create-snapshot <sandbox_id> --label s1       # returns status=pending
$CLI snapshot <snapshot_id>                        # dry-run worker flips it to ready in ~1-5s
$CLI stop <sandbox_id>                             # archiving -> archived
$CLI resume <sandbox_id> [--snapshot-id <uuid>]    # 202 + operation; archived -> provisioning -> ready
$CLI get <sandbox_id>; $CLI events <sandbox_id>; $CLI resources <sandbox_id>
```

Everything is asynchronous: the worker polls, so poll `get`/`snapshot` for a few
seconds rather than asserting immediately after the mutating call. Only `new`
has a `--wait`.

## Testing notes

- No Kubernetes cluster is needed for the dry-run provider, but apply-mode
  behavior (real CSI VolumeSnapshot restore, PVC clone) cannot be proven this
  way — say so explicitly rather than implying real restore was exercised.
- Postgres-backed runs: `just pg` starts a container and prints
  `SANDBOXWICH_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/sandboxwich`;
  the API accepts the same URL via `SANDBOXWICH_DATABASE_URL`.
- Direct job injection (`POST /v1/jobs`) is a useful adversarial path for
  worker-facing contracts, but note the tenant/authority validation for a
  directly-created job may not match the corresponding route's preconditions —
  test both surfaces separately rather than assuming they are equivalent.

## Devin Secrets Needed

None — all tokens above are local-only values you invent at start-up.
