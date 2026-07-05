# sandboxwich

A tiny, typed Rust control plane for disposable development sandboxes. It is intentionally early: the first slice gives us an API, CLI, durable event model, worker boundary, and guest-agent boundary that can grow into real VM orchestration.

The name is dumb on purpose. The contracts should not be.

## What exists now

- `sandboxwich-api`: HTTP control plane backed by SQLite for local dev or Postgres for shared deployments.
- `sandboxwich-cli`: CLI for creating, listing, stopping, resuming, forking, running commands, reading events, and inspecting runtime resources.
- `sandboxwich-core`: shared typed request/response/event contracts.
- `sandboxwich-worker`: host-side worker registration and heartbeat CLI.
- `sandboxwich-agent`: guest-side agent placeholder.

## Quick start

Run the API:

```sh
cargo run -p sandboxwich-api
```

In another shell:

```sh
cargo run -p sandboxwich-cli -- new --name demo
cargo run -p sandboxwich-cli -- list
cargo run -p sandboxwich-cli -- exec <sandbox-id> -- echo hello
cargo run -p sandboxwich-cli -- ssh <sandbox-id>
cargo run -p sandboxwich-cli -- prompt <sandbox-id> "inspect the repo"
cargo run -p sandboxwich-cli -- events <sandbox-id>
cargo run -p sandboxwich-cli -- resources <sandbox-id>
cargo run -p sandboxwich-worker -- register --name k3s-worker-a --provider kubernetes
cargo run -p sandboxwich-worker -- provider-smoke --cluster k3s-dev --namespace sandboxwich
cargo run -p sandboxwich-worker -- provider-apply-plan --cluster k3s-dev --namespace sandboxwich --ssh-authorized-keys-secret sandboxwich-authorized-keys
cargo run -p sandboxwich-worker -- run --name k3s-worker-a --max-iterations 1
cargo run -p sandboxwich-worker -- work-loop <worker-id> --max-iterations 1
cargo run -p sandboxwich-cli -- workers
```

By default the CLI talks to `http://127.0.0.1:3217`. Override it with `SANDBOXWICH_API`.

By default the API writes to `sqlite://sandboxwich.db`. Override it with `SANDBOXWICH_DATABASE_URL`, for example `postgres://sandboxwich:secret@localhost:5432/sandboxwich`.

The API exposes `/healthz`, `/readyz`, and `/metrics`. Set `SANDBOXWICH_API_TOKEN` to require bearer auth on API and metrics requests; `/healthz` and `/readyz` remain probe-friendly for Kubernetes.

Worker completions use typed result variants. Provider-created pods, PVCs, Services, and VolumeSnapshots are persisted as `runtime_resources` rows with constrained kind, purpose, and status columns; provider metadata is diagnostic compatibility data, not the durable source of runtime state.

## Design principles

- Typed state over text scraping.
- Durable events over inferred readiness.
- Worker and guest-agent boundaries from day one.
- Real isolation before real users.
- No committed runtime secrets.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current milestones.

For k3s and Kubernetes deployment notes, see [docs/kubernetes.md](docs/kubernetes.md).
