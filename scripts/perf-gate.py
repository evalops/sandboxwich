#!/usr/bin/env python3
"""Fail-closed performance gate: absolute budgets + optional baseline regression.

Reads JSON produced by scripts/perf-evaluate.py (or a compatible object with
`*_p95_ms` style keys). Exits non-zero on hard budget failure or a relative
regression against a baseline file when provided.

Usage:
  python3 scripts/perf-gate.py --current report.json
  python3 scripts/perf-gate.py --current report.json --baseline baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# Absolute p95 budgets (ms). Shared-runner noise is high; keep these ceilings
# production-protective, not micro-benchmark tight.
ABSOLUTE_P95_BUDGETS_MS: dict[str, float] = {
    "warm_startup_p95_ms": 2_000.0,
    "healthz_p95_ms": 500.0,
    "readyz_p95_ms": 500.0,
    "sandboxes_list_p95_ms": 2_000.0,
    "sandboxes_create_p95_ms": 2_000.0,
    "ttft_total_p95_ms": 5_000.0,
}

# Relative regression threshold vs baseline (fraction). 0.35 = +35%.
DEFAULT_REGRESSION_THRESHOLD = 0.35


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def check_absolute(metrics: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if metrics.get("benchmark_completed") != 1:
        failures.append("benchmark_completed != 1")
    request_failures = metrics.get("request_failures")
    if request_failures not in (None, 0):
        failures.append(f"request_failures={request_failures}")
    for key, limit in ABSOLUTE_P95_BUDGETS_MS.items():
        value = metrics.get(key)
        if value is None:
            # Optional keys: skip if this profile omits the metric.
            continue
        try:
            p95 = float(value)
        except (TypeError, ValueError):
            failures.append(f"{key} is not numeric: {value!r}")
            continue
        if p95 > limit:
            failures.append(f"{key}={p95:.2f} exceeds absolute budget {limit:.0f}ms")
    return failures


def check_regression(
    current: dict[str, Any],
    baseline: dict[str, Any],
    threshold: float,
) -> list[str]:
    failures: list[str] = []
    for key, limit in ABSOLUTE_P95_BUDGETS_MS.items():
        if key not in current or key not in baseline:
            continue
        try:
            cur = float(current[key])
            base = float(baseline[key])
        except (TypeError, ValueError):
            continue
        if base <= 0:
            continue
        # Only flag regressions that also approach the absolute budget so
        # ultra-fast noisy baselines (sub-ms) do not trip the gate.
        if cur > base * (1.0 + threshold) and cur > min(limit * 0.25, base * 3.0):
            pct = (cur / base - 1.0) * 100.0
            failures.append(
                f"{key} regressed {pct:.1f}% vs baseline "
                f"(current={cur:.2f}ms baseline={base:.2f}ms threshold={threshold*100:.0f}%)"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument(
        "--regression-threshold",
        type=float,
        default=DEFAULT_REGRESSION_THRESHOLD,
        help="Relative p95 growth vs baseline that fails the gate (default 0.35)",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        help="If set, write current metrics to this path after a successful gate",
    )
    args = parser.parse_args()

    current = load_json(args.current)
    failures = check_absolute(current)
    if args.baseline is not None and args.baseline.is_file():
        baseline = load_json(args.baseline)
        failures.extend(
            check_regression(current, baseline, args.regression_threshold)
        )
    elif args.baseline is not None:
        print(
            f"baseline {args.baseline} missing; absolute budgets only",
            file=sys.stderr,
        )

    if failures:
        print("perf gate FAILED:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print("perf gate OK")
    if args.write_baseline is not None:
        args.write_baseline.parent.mkdir(parents=True, exist_ok=True)
        args.write_baseline.write_text(json.dumps(current, sort_keys=True, indent=2) + "\n")
        print(f"wrote baseline {args.write_baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
