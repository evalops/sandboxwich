---
name: api-runtime-testing
description: Use when runtime-testing the sandboxwich-api HTTP surface end-to-end against a real locally running server (not just cargo test) — covers auth setup, SQLite/Postgres backends, and secret/tenant-scoping verification.
---

# Runtime-testing `sandboxwich-api` locally

`sandboxwich-api` is a headless HTTP API. There is no UI, so runtime testing is
curl against a real server process; do not record a screen session for it.

## Start a server

```sh
cargo build -p sandboxwich-api
SANDBOXWICH_DATABASE_URL="sqlite:///tmp/sbw/sbw.db" \
SANDBOXWICH_BIND=127.0.0.1:8099 \
SANDBOXWICH_TENANT_TOKENS="default=tok-default,tenant-b=tok-b" \
SANDBOXWICH_OPERATOR_TOKEN=op-tok \
./target/debug/sandboxwich-api > /tmp/sbw/server.log 2>&1 &
```

- Auth is **fail-closed**: with no `SANDBOXWICH_TENANT_TOKENS` (or
  `SANDBOXWICH_API_TOKEN`) every route 401s. The token format is
  `tenant=token,tenant2=token2` — mirror
  `crates/sandboxwich-api/tests/http_contract/common.rs` (`TestServer::start_with_auth`),
  which configures two tenants precisely so isolation can be tested with real
  credentials. Two tenants is the minimum useful config.
- The tenant comes from the bearer token only. `x-sandboxwich-tenant-id` is not
  trusted and must never change the answer — a good adversarial check.
- Routes live under `/v1` (`/v1/healthz`, `/v1/readyz`, `/v1/openapi.json`);
  `/v1/openapi.json` requires auth too.
- Migrations run automatically on boot unless `SANDBOXWICH_AUTO_MIGRATE=false`.
  Disable the background sweeper with `SANDBOXWICH_DISABLE_EXPIRY_SWEEPER` if a
  test needs stable rows.

## Postgres backend

Same binary, different URL; run it on a second port alongside the SQLite one so
both backends are exercised in one pass:

```sh
docker run -d --rm --name sbw-pg -e POSTGRES_USER=sandboxwich -e POSTGRES_PASSWORD=sandboxwich \
  -e POSTGRES_DB=sandboxwich -p 55432:5432 postgres:16
SANDBOXWICH_DATABASE_URL="postgres://sandboxwich:sandboxwich@127.0.0.1:55432/sandboxwich" ...
docker exec sbw-pg psql -U sandboxwich -d sandboxwich -c '\d some_table'
```

`psql` is usually not installed on the host — go through `docker exec`. Boot logs
emit benign `... does not exist, skipping` notices from idempotent migrations;
they are not failures. Unique-constraint / partial-index behaviour can differ
between SQLite and Postgres, so re-run conflict (409) and idempotency assertions
on both.

## Verifying secret / credential-leak claims

When a change claims "no credential material can be stored or returned":

1. Pick a canary string and use a **distinct** canary for the material tests than
   for any value you legitimately store (object names/keys accept many
   characters — storing your canary there will confound the DB grep).
2. Rejected bodies should return 422 (serde `deny_unknown_fields`) with a generic
   message that does not echo the submitted body.
3. Grep server stdout/stderr logs, `strings` the SQLite file, and — most
   importantly — sweep **every table**, not just the new one:
   `for t in sqlite_master tables: select * from t` and search the row tuples.
   Also dump `pragma table_info(<table>)` / `\d <table>` to prove no column
   exists that could hold material.
4. Check the derived surfaces too: queued job payloads and sandbox
   `provider_metadata` are persisted and tenant-visible (see AGENTS.md).

## Tenant-scoping checks that actually distinguish broken from working

- Cross-tenant GET/DELETE must be **404, not 403** (no existence oracle).
- After a cross-tenant DELETE returns 404, re-read as the owning tenant and
  assert the row is still `active` — otherwise you have not proven the request
  was scoped out rather than executed.
- Fire 5 parallel identical creates to prove the uniqueness index (not just an
  application-level pre-check) enforces the conflict: expect one 201 and N-1
  409s, and exactly one row in the DB.

## Devin Secrets Needed

None. Tokens are invented locally via `SANDBOXWICH_TENANT_TOKENS`; no external
credentials are required.
