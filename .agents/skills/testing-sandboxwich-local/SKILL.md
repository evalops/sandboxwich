---
name: testing-sandboxwich-local
description: Run sandboxwich-api plus a dry-run worker locally and drive sandbox lifecycle flows (create/snapshot/stop/resume/fork) end-to-end through the CLI and raw HTTP for manual or agentic testing.
---

# Local end-to-end testing of sandboxwich

Use this when you need a real running control plane (not unit tests) to exercise
sandbox lifecycle behavior: provision, snapshot, stop, resume, fork, jobs, leases.

## Build

```sh
cargo build -p sandboxwich-api -p sandboxwich-worker -p sandboxwich-cli
```

The CLI binary is `target/debug/sandboxwich` (NOT `sandboxwich-cli`); the crate
name and the binary name differ, which is easy to trip over when invoking the
built binary directly instead of `cargo run -p sandboxwich-cli --`.

## Start the API

```sh
mkdir -p /tmp/sbwtest && cd /tmp/sbwtest && rm -f test.db*
SANDBOXWICH_TENANT_TOKENS="acme=acme-token,globex=globex-token" \
SANDBOXWICH_DATABASE_URL="sqlite:///tmp/sbwtest/test.db?mode=rwc" \
  target/debug/sandboxwich-api serve
```

- Use `SANDBOXWICH_TENANT_TOKENS` (not `SANDBOXWICH_API_TOKEN`) whenever the test
  involves cross-tenant isolation: with a single shared token every request is
  forced onto `SANDBOXWICH_DEFAULT_TENANT` and a client-supplied
  `x-sandboxwich-tenant` header is ignored, so a "cross-tenant" test would prove
  nothing. Tenant identity comes only from which bearer token matched.
- A second API instance against Postgres for a dialect check:
  `SANDBOXWICH_BIND=127.0.0.1:3218 SANDBOXWICH_DATABASE_URL=postgres://postgres:postgres@localhost:5432/sandboxwich`
  (`just pg` starts a suitable container). Point the CLI/worker at it with
  `SANDBOXWICH_API=http://127.0.0.1:3218/v1`.

## Start a dry-run worker (gotchas)

```sh
SANDBOXWICH_API_TOKEN=acme-token \
SANDBOXWICH_RUNTIME_IMAGE="ghcr.io/evalops/sandboxwich-runtime@sha256:<64 hex chars>" \
setsid nohup target/debug/sandboxwich-worker run \
  --name local-dry-run --provider kubernetes --provider-mode dry-run \
  > worker.log 2>&1 < /dev/null &
```

- The worker reads its bearer token from `SANDBOXWICH_API_TOKEN`; there is no
  `--api-token` argument on the `run` subcommand.
- `SANDBOXWICH_RUNTIME_IMAGE` **must** be pinned by sha256 digest even in dry-run
  mode. Without it `POST /v1/sandboxes` fails with
  `500 {"code":"internal","message":"worker placement runtime image is not digest-pinned"}`.
  Any syntactically valid `@sha256:<64 hex>` reference works; it is never pulled.
- Start the worker with `setsid`/`disown` from agent shells; a plain background
  job gets a shutdown signal when the spawning shell exits and the worker logs
  "shutdown requested", which then looks like jobs mysteriously never being claimed.
- **One worker per tenant.** Jobs are tenant-scoped, so a sandbox created under a
  second tenant sits in `Planning` forever unless that tenant also has a worker.
- Beware `pkill -f "…worker run --name X"` from an agent shell: the pattern also
  matches the `bash -c` wrapper running the command, killing your own shell. Use a
  bracket pattern (`pkill -f "local-dry-run[-]3"`) or `kill <pid>`.

## Golden lifecycle through the CLI

```sh
export SANDBOXWICH_API_TOKEN=acme-token
CLI=target/debug/sandboxwich
$CLI new --name demo --memory-limit 4g --wait      # workspace_mode defaults to persistent
$CLI create-snapshot <sandbox_id> --label s1       # returns status=pending, ready in ~1-5s
$CLI stop <sandbox_id>                             # archiving -> archived (needs a live worker!)
$CLI resume <sandbox_id> [--snapshot-id <uuid>]    # 202 + operation; archived -> provisioning -> ready
$CLI get/events/resources <sandbox_id>
```

Everything except `new --wait` is asynchronous — poll for a few seconds. The
runtime-resource route is `GET /v1/sandboxes/{id}/runtime-resources` (the CLI
subcommand is `resources`). Lifecycle event payloads are under the `data` key.

## Driving worker-facing contracts by hand

To test lease claim/complete validation (mismatched handles, bad resource rows)
stop the auto worker and register your own:

```sh
curl -sX POST $API/workers/register -H "$AUTH" -H 'content-type: application/json' -d '{
  "name":"manual","provider":"kubernetes","capabilities":["k8s_pod","provision_sandbox","run_command","snapshot"],
  "max_concurrent_jobs":1,"labels":{"provider_mode":"dry-run","runtime_image":"<digest-pinned>"}}'
# response contains worker_token -> use it as the bearer for lease routes
curl -sX POST $API/workers/<worker_id>/leases/claim -H "Authorization: Bearer $WORKER_TOKEN" \
  -d '{"lease_seconds":300,"kinds":["resume_sandbox"]}'
curl -sX POST $API/leases/<lease_id>/complete -H "Authorization: Bearer $WORKER_TOKEN" \
  -d '{"result":{"kind":"resume_sandbox","handle":{…}}}'
```

Capability matters: fork/resume jobs require the `snapshot` capability
(`fork_capability()` in handlers/sandboxes.rs), so a worker registered with only
`k8s_pod` silently claims nothing and `leases/claim` returns `{"lease":null}`.

## Testing notes

- Dry-run resources are recorded with status `planned` and are updated **in place**
  on re-provision/resume (same row id), so "a new generation of rows" is not what
  you should assert; assert on `status`, `deleted_at` and `source_snapshot_id`.
- No Kubernetes cluster is needed, but apply-mode behavior (real CSI VolumeSnapshot
  restore, PVC clone, rollback) cannot be proven this way — say so explicitly rather
  than implying real restore was exercised.
- Watch for provider methods that exist on `KubernetesDryRunProvider`/
  `KubernetesApplyProvider` but are **not forwarded by the `RuntimeProvider` enum**
  in `crates/sandboxwich-worker/src/main.rs`: the trait has default impls that
  `bail!`, so a missing match arm compiles fine, passes provider-level unit tests,
  and only fails at runtime with "provider cannot restore durable state" style
  errors. Always exercise new provider verbs through the real worker binary, and
  prefer unit tests that dispatch through `RuntimeProvider::DryRun(...)`.
- Direct job injection (`POST /v1/jobs`) is a useful adversarial path: verify that
  route-level preconditions are re-enforced there, not just tenant ownership.

## Devin Secrets Needed

None — all tokens above are local-only values you invent at start-up.
