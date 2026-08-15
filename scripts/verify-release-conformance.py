#!/usr/bin/env python3
"""Require a successful live conformance run for an exact release commit."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

SCHEMA = "sandboxwich.release-conformance.v1"
DEFAULT_WORKFLOW = "kubernetes-conformance.yml"
API_VERSION = "2022-11-28"
ACTIVE_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Wait for a successful GitHub Actions workflow run whose head SHA "
            "exactly matches the release commit, then write a machine-readable attestation."
        )
    )
    parser.add_argument("--sha", required=True, help="Exact 40-character commit SHA")
    parser.add_argument(
        "--workflow",
        default=DEFAULT_WORKFLOW,
        help="Workflow file name or numeric workflow id",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=1800,
        help="Maximum time to wait for a matching workflow run",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=20,
        help="Delay between GitHub API polls",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("release-conformance-attestation.json"),
        help="Attestation output path",
    )
    return parser.parse_args()


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def validate_args(args: argparse.Namespace) -> None:
    if not SHA_RE.fullmatch(args.sha):
        raise SystemExit("--sha must be exactly 40 lowercase hexadecimal characters")
    if args.timeout_seconds < 0:
        raise SystemExit("--timeout-seconds must be non-negative")
    if args.poll_seconds <= 0:
        raise SystemExit("--poll-seconds must be positive")


def fetch_runs(
    *,
    api_url: str,
    repository: str,
    workflow: str,
    sha: str,
    token: str,
) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"head_sha": sha, "per_page": 100})
    workflow_path = urllib.parse.quote(workflow, safe="")
    url = (
        f"{api_url.rstrip('/')}/repos/{repository}/actions/workflows/"
        f"{workflow_path}/runs?{query}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "sandboxwich-release-conformance",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"GitHub workflow-runs request failed with HTTP {error.code}: {body}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"GitHub workflow-runs request failed: {error}") from error

    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise RuntimeError("GitHub workflow-runs response omitted workflow_runs")
    return [run for run in runs if isinstance(run, dict) and run.get("head_sha") == sha]


def parse_created_at(run: dict[str, Any]) -> str:
    value = run.get("created_at")
    return value if isinstance(value, str) else ""


def newest(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    return max(runs, key=parse_created_at, default=None)


def successful_run(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    successful = [
        run
        for run in runs
        if run.get("status") == "completed" and run.get("conclusion") == "success"
    ]
    return newest(successful)


def active_run(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    active = [run for run in runs if run.get("status") in ACTIVE_STATUSES]
    return newest(active)


def completed_run(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    completed = [run for run in runs if run.get("status") == "completed"]
    return newest(completed)


def write_attestation(
    output: pathlib.Path,
    *,
    sha: str,
    workflow: str,
    run: dict[str, Any],
) -> None:
    run_id = run.get("id")
    run_url = run.get("html_url")
    if not isinstance(run_id, int) or not isinstance(run_url, str):
        raise RuntimeError("successful workflow run omitted id or html_url")

    attestation = {
        "schema": SCHEMA,
        "commit": sha,
        "workflow": workflow,
        "workflowRunId": run_id,
        "workflowRunUrl": run_url,
        "conclusion": "success",
        "verifiedAt": dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, output)
    print(json.dumps(attestation, sort_keys=True))


def main() -> int:
    args = parse_args()
    validate_args(args)

    api_url = required_env("GITHUB_API_URL")
    repository = required_env("GITHUB_REPOSITORY")
    token = required_env("GITHUB_TOKEN")
    deadline = time.monotonic() + args.timeout_seconds
    last_description = "no matching workflow run is visible"

    while True:
        try:
            runs = fetch_runs(
                api_url=api_url,
                repository=repository,
                workflow=args.workflow,
                sha=args.sha,
                token=token,
            )
        except RuntimeError as error:
            last_description = str(error)
            runs = []

        success = successful_run(runs)
        if success is not None:
            write_attestation(
                args.output,
                sha=args.sha,
                workflow=args.workflow,
                run=success,
            )
            return 0

        active = active_run(runs)
        completed = completed_run(runs)
        if active is not None:
            last_description = (
                f"workflow run {active.get('id')} is {active.get('status')}"
            )
        elif completed is not None:
            conclusion = completed.get("conclusion") or "unknown"
            run_url = completed.get("html_url") or completed.get("url") or "unknown URL"
            raise SystemExit(
                "exact-SHA conformance failed: "
                f"run {completed.get('id')} concluded {conclusion}: {run_url}"
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SystemExit(
                "timed out waiting for exact-SHA conformance for "
                f"{args.sha}: {last_description}"
            )
        print(
            f"waiting for {args.workflow} at {args.sha}: {last_description}",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(min(args.poll_seconds, remaining))


if __name__ == "__main__":
    raise SystemExit(main())
