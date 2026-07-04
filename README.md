# sandboxwich

A tiny, typed Rust control plane for disposable development sandboxes. It is intentionally early: the first slice gives us an API, CLI, durable event model, worker boundary, and guest-agent boundary that can grow into real VM orchestration.

The name is dumb on purpose. The contracts should not be.

## What exists now

- `sandboxwich-api`: HTTP control plane backed by a local SQLite database by default.
- `sandboxwich-cli`: CLI for creating, listing, stopping, resuming, forking, running commands, and reading events.
- `sandboxwich-core`: shared typed request/response/event contracts.
- `sandboxwich-worker`: host-side worker placeholder.
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
cargo run -p sandboxwich-cli -- events <sandbox-id>
```

By default the CLI talks to `http://127.0.0.1:3217`. Override it with `SANDBOXWICH_API`.

By default the API writes to `sqlite://sandboxwich.db`. Override it with `SANDBOXWICH_DATABASE_URL`.

## Design principles

- Typed state over text scraping.
- Durable events over inferred readiness.
- Worker and guest-agent boundaries from day one.
- Real isolation before real users.
- No committed runtime secrets.

## Roadmap

1. Persist state in Postgres.
2. Add a real worker lease queue.
3. Add SSH key injection and command streaming.
4. Add disk snapshot/fork support.
5. Add a desktop stream broker.
6. Add provider adapters for VM and microVM backends.
