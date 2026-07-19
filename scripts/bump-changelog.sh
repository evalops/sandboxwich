#!/usr/bin/env bash
set -euo pipefail

# Idempotently insert a dated version header under "## Unreleased" in the
# workspace CHANGELOG. cargo-release invokes this hook once per crate, so the
# idempotency guard keeps only the first invocation from editing the file.

ROOT="$(git rev-parse --show-toplevel)"
CHANGELOG="${ROOT}/CHANGELOG.md"
VERSION="${1:-}"

if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

if ! [[ -f "${CHANGELOG}" ]]; then
  echo "CHANGELOG not found: ${CHANGELOG}" >&2
  exit 1
fi

if grep -qE "^## ${VERSION} - " "${CHANGELOG}"; then
  exit 0
fi

DATE="$(date -u +%Y-%m-%d)"

# Insert the new header directly under the Unreleased heading.
sed -i \
  "0,/^## Unreleased$/{s/^## Unreleased$/## Unreleased\\n\\n## ${VERSION} - ${DATE}/}" \
  "${CHANGELOG}"
