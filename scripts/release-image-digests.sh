#!/usr/bin/env bash
set -euo pipefail

grep -hE '^[[:space:]]*(image:|value:)[[:space:]]+ghcr\.io/evalops/sandboxwich-(api|worker|ubuntu-dev)@sha256:[0-9a-f]{64}$' \
  deploy/kubernetes/*.yaml |
  sed -E 's/^[[:space:]]*(image:|value:)[[:space:]]*//' |
  sort -u
