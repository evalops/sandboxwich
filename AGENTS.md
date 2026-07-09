# Agent instructions for sandboxwich

Conventions for AI agents (and humans) working in this repo. Most of these were
paid for during the 2026-07-09 audit wave (PRs #94–#110); the incident details
live in the linked PRs.

## Build and gates

Every change must pass, locally, before pushing:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- The workspace sets `unsafe_code = "forbid"`. Do not write `unsafe`; if a fix
  seems to need it, use a vetted crate that encapsulates it (e.g. cap-std) or
  redesign.
- When scripting gates, check the test command's own exit code. Piping
  `cargo test` through `grep`/`tail` makes the pipeline report the filter's
  exit code and converts a red gate into a green one. Use `set -o pipefail`
  or run the command bare and filter its captured output afterwards.
- Postgres-backed contract tests only run when `SANDBOXWICH_TEST_POSTGRES_URL`
  is set; they isolate per-test databases automatically (#94). Say in your PR
  whether they ran locally.

## Landing PRs

- Merge commits, never squash — branches carry deliberately atomic commits.
- Never force-push a branch that has been pushed. Land corrections as new
  commits.
- **Individually CI-green PRs do not compose.** A PR's checks ran against the
  main that existed when its branch last moved, and GitHub's CLEAN merge
  status only rules out *textual* conflicts. Before merging — even when
  CLEAN — merge current `main` into the branch, run the full gate locally,
  push, and let CI pass on the true integration state. One wave produced
  three semantic conflicts this way: a new test calling routes another PR had
  just locked down (#96×#98, broke main, fixed by #106), and two line-merges
  that produced non-compiling or panicking code (#97×#99, #97/#99×#100).
- After merging anything that touches a shared hot file
  (`crates/sandboxwich-worker/src/provider.rs`, the api handlers, the
  http_contract common harness), audit **all** call sites of the functions
  touched — clean auto-merges happily produce stale argument lists.
- After merge, verify the `Closes #N` reference actually closed the issue;
  it silently fails to link sometimes (#109/#101).

## Secrets

- Secret values never go on argv (visible in `/proc/*/cmdline` and `ps`).
  Deliver via stdin (see `EXEC_ENV_WRAPPER_SCRIPT` in the worker provider) or
  mounted Secret files (see the worker-token flow from #109).
- **Provider handle metadata is persisted and tenant-visible.** Anything put
  in `ProviderSandboxHandle`/`ProviderForkHandle` metadata is written to
  `sandboxes.provider_metadata` and returned on sandbox reads. Raw secret
  bytes are allowed only in the manifest sets physically applied via kubectl
  stdin; every serialized/persisted/printed rendering must use the redacted
  variant (`WORKER_TOKEN_REDACTED` pattern, #109).
- When adding a new secret-bearing input, register it in the canary-token
  sweep (issue #111) and trace every serialization sink: DB columns, API
  response bodies, plan/diagnostic output, log lines, stored job stdout.

## Test conventions

- In concurrency tests, assert *outcomes*, not *actors*: "the snapshot ends
  up expired", never "this component expired it". Who-did-it assertions pass
  or fail by race luck (#94, #100).
- Guest-facing lease routes (`leases/claim`, `leases/.../complete`, …) reject
  tenant-wide tokens; tests must use `worker_client(&worker)` (#96 — the
  #96×#98 incident was a new test using the plain tenant client).
- Synchronous `#[test]`s may call provider methods that internally drive
  async kubectl invocations — there is a runtime fallback in
  `run_kubectl_command_with_stdin` — but prefer `#[tokio::test]` for new
  async-adjacent tests.
- `TestServer::spawn` retries lost port-bind races automatically (#108);
  don't add sleeps or port hacks around it.

## Layout

- `crates/sandboxwich-api/src/main.rs` is a thin entrypoint; code lives in
  the modules split out in #110 (`handlers/` by resource family, `db.rs`,
  `auth.rs`, `scheduler.rs`, `cleanup.rs`, …). Keep new code in the matching
  module; don't grow main.rs back.
- The http_contract test is split the same way under
  `tests/http_contract/`; shared harness in `common.rs`.
