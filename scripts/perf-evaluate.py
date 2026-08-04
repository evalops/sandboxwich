#!/usr/bin/env python3
"""Run the representative benchmark and emit fail-closed optimization JSON.

The production benchmark intentionally emits a human-readable Markdown report.
This adapter keeps that public format unchanged while providing the strict JSON
contract required by the local optimization loop. Any missing or malformed row
is an error rather than a silently incomplete measurement.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Final


ROOT: Final = Path(__file__).resolve().parent.parent
API_BIN: Final = ROOT / "target/debug/sandboxwich-api"
WORKER_BIN: Final = ROOT / "target/debug/sandboxwich-worker"
BENCH_BIN: Final = ROOT / "target/debug/sandboxwich-bench"

HTTP_SECTIONS: Final = {
    "warm startup": ("warm_startup", 2_000.0),
    "GET /healthz": ("healthz", 500.0),
    "GET /readyz": ("readyz", 500.0),
    "GET /sandboxes": ("sandboxes_list", 2_000.0),
}
POST_SECTION_PREFIX: Final = "POST /sandboxes"
POST_METRIC_PREFIX: Final = "sandboxes_create"
POST_P95_BUDGET_MS: Final = 2_000.0
TTFT_SECTION: Final = "Sandbox TTFT (dry-run k8s worker)"
TTFT_ROWS: Final = {
    "total TTFT": "ttft_total",
    "create sandbox request": "ttft_create",
    "queue provision job": "ttft_queue_provision",
    "provision job queued -> succeeded": "ttft_provision_ready",
    "queue command request": "ttft_queue_command",
    "command queued -> first output": "ttft_first_output",
}
TTFT_P95_BUDGET_MS: Final = 5_000.0
MILLISECONDS: Final = re.compile(r"^(\d+(?:\.\d+)?)ms$")


class ReportError(ValueError):
    """The benchmark report is incomplete or has changed shape."""


def parse_milliseconds(value: str, context: str) -> float:
    match = MILLISECONDS.fullmatch(value.strip())
    if match is None:
        raise ReportError(f"{context}: expected milliseconds, got {value!r}")
    return float(match.group(1))


def table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_report(report: str, wall_seconds: float) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    section: str | None = None
    request_failures = 0
    normalized_p95: list[float] = []
    seen_http: set[str] = set()
    seen_ttft: set[str] = set()

    for line_number, line in enumerate(report.splitlines(), start=1):
        if line.startswith("## "):
            section = line.removeprefix("## ").strip()
            continue
        if not line.startswith("|") or section is None:
            continue

        cells = table_cells(line)
        if cells[0] in {"requests", "phase"} or cells[0].startswith("---"):
            continue

        http_definition = HTTP_SECTIONS.get(section)
        if section.startswith(POST_SECTION_PREFIX):
            http_definition = (POST_METRIC_PREFIX, POST_P95_BUDGET_MS)
        if http_definition is not None:
            if len(cells) != 9 or not cells[0].isdigit() or not cells[1].isdigit():
                raise ReportError(
                    f"line {line_number}: malformed HTTP row in section {section!r}"
                )
            prefix, p95_budget_ms = http_definition
            if prefix in seen_http:
                raise ReportError(f"duplicate HTTP row for {section!r}")
            seen_http.add(prefix)
            failures = int(cells[1])
            request_failures += failures
            try:
                rps = float(cells[2])
            except ValueError as error:
                raise ReportError(
                    f"line {line_number}: invalid RPS {cells[2]!r}"
                ) from error
            p95_ms = parse_milliseconds(cells[5], f"line {line_number} p95")
            metrics[f"{prefix}_p95_ms"] = p95_ms
            if prefix != "warm_startup":
                metrics[f"{prefix}_rps"] = rps
            normalized_p95.append(p95_ms / p95_budget_ms)
            continue

        if section == TTFT_SECTION and cells[0] in TTFT_ROWS:
            if len(cells) != 8 or not cells[1].isdigit():
                raise ReportError(
                    f"line {line_number}: malformed TTFT row {cells[0]!r}"
                )
            prefix = TTFT_ROWS[cells[0]]
            if prefix in seen_ttft:
                raise ReportError(f"duplicate TTFT row {cells[0]!r}")
            seen_ttft.add(prefix)
            p95_ms = parse_milliseconds(cells[4], f"line {line_number} p95")
            metrics[f"{prefix}_p95_ms"] = p95_ms
            if prefix == "ttft_total":
                normalized_p95.append(p95_ms / TTFT_P95_BUDGET_MS)

    expected_http = {definition[0] for definition in HTTP_SECTIONS.values()}
    expected_http.add(POST_METRIC_PREFIX)
    missing_http = sorted(expected_http - seen_http)
    missing_ttft = sorted(set(TTFT_ROWS.values()) - seen_ttft)
    if missing_http or missing_ttft:
        raise ReportError(
            f"incomplete benchmark report: missing HTTP={missing_http}, TTFT={missing_ttft}"
        )
    if len(normalized_p95) != 6:
        raise ReportError(
            f"expected six budget-normalized p95 values, got {len(normalized_p95)}"
        )

    metrics["request_failures"] = request_failures
    metrics["benchmark_completed"] = 1
    metrics["benchmark_wall_seconds"] = round(wall_seconds, 6)
    metrics["budget_normalized_p95_pct"] = round(
        sum(normalized_p95) * 100.0 / len(normalized_p95), 6
    )
    return metrics


def ensure_binaries() -> None:
    if all(binary.is_file() for binary in (API_BIN, WORKER_BIN, BENCH_BIN)):
        return
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "sandboxwich-api",
            "-p",
            "sandboxwich-worker",
            "-p",
            "sandboxwich-bench",
        ],
        cwd=ROOT,
        check=True,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )


def run_benchmark() -> tuple[str, float]:
    command = [
        str(BENCH_BIN),
        "all",
        "--api-bin",
        str(API_BIN),
        "--worker-bin",
        str(WORKER_BIN),
        "--runs",
        "5",
        "--ttft-runs",
        "10",
        "--requests",
        "300",
        "--concurrency",
        "25",
        "--seed-sandboxes",
        "250",
    ]
    environment = os.environ.copy()
    environment["SANDBOXWICH_ALLOW_INSECURE_NO_AUTH"] = "true"
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wall_seconds = time.perf_counter() - started
    if completed.returncode != 0:
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        raise RuntimeError(f"benchmark exited with status {completed.returncode}")
    return completed.stdout, wall_seconds


def main() -> int:
    try:
        ensure_binaries()
        report, wall_seconds = run_benchmark()
        metrics = parse_report(report, wall_seconds)
    except (OSError, ReportError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"performance measurement failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(metrics, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
