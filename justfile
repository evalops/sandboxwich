# Common local operations. See README.md for the full quick start and
# AGENTS.md for the required pre-push gate this `gate` recipe mirrors.
#
# `just --list` shows this file's recipes.

# The AGENTS.md gate, exactly: fmt --check, clippy -D warnings, then
# test --workspace. `just` runs each recipe line as its own command and
# aborts on the first non-zero exit, so this gets real exit-code
# propagation for free -- no piping cargo test through grep/tail, which
# AGENTS.md calls out as the way to accidentally turn a red gate green.
gate:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# Bump the workspace version, update CHANGELOG.md, commit, and push a tag.
# Run `just release patch`, `just release minor`, `just release 0.2.0`, etc.
release bump="patch":
    cargo release {{ bump }} --execute --no-publish --no-verify

# Dry-run a version bump to see what cargo-release would change.
release-dry-run bump="patch":
    cargo release {{ bump }} --no-publish --no-verify

# Run the API and a dry-run worker together, using the same flags as the
# README quick start's first two shells and a local-only dev token. Ctrl-C
# stops both. Dry-run mode validates the control-plane flow but never
# mutates a cluster.
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    export SANDBOXWICH_API_TOKEN="${SANDBOXWICH_API_TOKEN:-local-development-token}"
    cargo run -p sandboxwich-api -- serve &
    api_pid=$!
    cargo run -p sandboxwich-worker -- run \
      --name local-dry-run \
      --provider kubernetes \
      --provider-mode dry-run &
    worker_pid=$!
    trap 'kill "${api_pid}" "${worker_pid}" 2>/dev/null || true; wait' EXIT INT TERM
    wait -n "${api_pid}" "${worker_pid}"

# Start a dockerized Postgres for the Postgres-backed contract tests
# (SANDBOXWICH_TEST_POSTGRES_URL) and print the export line once it's ready
# to accept connections. Stop it with: docker stop sandboxwich-dev-postgres
pg:
    #!/usr/bin/env bash
    set -euo pipefail
    docker run --rm -d --name sandboxwich-dev-postgres \
      -e POSTGRES_DB=sandboxwich \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_PASSWORD=postgres \
      -p 5432:5432 \
      postgres:17 >/dev/null
    echo "waiting for postgres to accept connections..." >&2
    until docker exec sandboxwich-dev-postgres pg_isready -U postgres >/dev/null 2>&1; do
      sleep 1
    done
    echo "export SANDBOXWICH_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/sandboxwich"

# Run the Python SDK's test suite (sdks/python), creating its venv on first use.
# See sdks/python/README.md for the full quickstart, auth, and examples.
py-test:
    #!/usr/bin/env bash
    set -euo pipefail
    cd sdks/python
    if [ ! -d .venv ]; then
      python3 -m venv .venv
    fi
    . .venv/bin/activate
    pip install -q -e ".[dev]"
    pytest
