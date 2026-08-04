#!/usr/bin/env python3
"""Identify sandboxwich control-plane performance regressions and wins.

Commands
--------
  scenarios  List scenario definitions.
  measure    Run one scenario N times; emit median/range/stddev + bottleneck rank.
  ab         Interleaved A/B of two binary trees (or git refs) for one scenario.
  matrix     Run scenarios; rank by opportunity score (headroom × stability).
  bottleneck Rank every latency metric inside a measure/matrix JSON run.
  compare    Diff two JSON runs (measure or ab); per-metric KEEP/NOISY/REJECT.
  report     Pretty-print a saved JSON run for review.
  history    List recent .perf/runs artifacts.
  ledger     Append or list hypothesis results (.perf/hypotheses.jsonl).

Design goals
------------
- Fail closed: missing metrics or non-zero request_failures are hard errors.
- Noise-aware: declare a primary metric and noise threshold; A/B prints KEEP/REJECT/NOISY.
- Scenario-shaped: allowlist-heavy list, scale list, create, TTFT, smoke, full suite.
- Multi-metric: surface secondary bottlenecks, not only the scenario primary.
- Release-first: defaults to release binaries so decode/serialize cost is real.
- Comparable: every run is JSON under .perf/runs/; compare/bottleneck/report read them.

Examples
--------
  python3 scripts/perf-harness.py matrix --profile release --repeats 3
  python3 scripts/perf-harness.py measure --scenario allowlist --profile release
  python3 scripts/perf-harness.py bottleneck --run .perf/runs/latest-measure.json
  python3 scripts/perf-harness.py ab --baseline-ref origin/main --scenario allowlist --pairs 5
  python3 scripts/perf-harness.py compare --before a.json --after b.json --noise 5
  python3 scripts/perf-harness.py ledger --list
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Final


ROOT: Final = Path(__file__).resolve().parent.parent
PERF_DIR: Final = ROOT / ".perf"
RUNS_DIR: Final = PERF_DIR / "runs"
LEDGER_PATH: Final = PERF_DIR / "hypotheses.jsonl"

# Reuse the existing fail-closed report parser (hyphenated filename).
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "perf_evaluate",
    Path(__file__).resolve().parent / "perf-evaluate.py",
)
assert _spec is not None and _spec.loader is not None
perf_evaluate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(perf_evaluate)

# Latency metrics we expect from a full HTTP suite (optional TTFT when ttft_runs>0).
LATENCY_SUFFIX: Final = "_p95_ms"
BUDGETS_MS: Final[dict[str, float]] = {
    "warm_startup_p95_ms": 2_000.0,
    "healthz_p95_ms": 500.0,
    "readyz_p95_ms": 500.0,
    "sandboxes_list_p95_ms": 2_000.0,
    "sandboxes_create_p95_ms": 2_000.0,
    "ttft_total_p95_ms": 5_000.0,
    "ttft_create_p95_ms": 5_000.0,
    "ttft_queue_provision_p95_ms": 5_000.0,
    "ttft_provision_ready_p95_ms": 5_000.0,
    "ttft_queue_command_p95_ms": 5_000.0,
    "ttft_first_output_p95_ms": 5_000.0,
}


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS: Final[dict[str, dict[str, Any]]] = {
    "smoke": {
        "description": "Fast local iteration (small seed, few requests).",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 15.0,
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 50,
        "requests": 80,
        "concurrency": 10,
        "runs": 2,
        "ttft_runs": 0,
    },
    "default": {
        "description": "Representative control-plane suite (deny_all seed).",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 10.0,
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 250,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 10,
    },
    "allowlist": {
        "description": "GET /sandboxes under allowlist-heavy seed (rules embedded).",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 10.0,
        "allowlist_fraction": 1.0,
        "allowlist_rules_per_sandbox": 5,
        "seed_sandboxes": 250,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 0,
    },
    "allowlist_mixed": {
        "description": "Half allowlist / half deny_all list traffic.",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 10.0,
        "allowlist_fraction": 0.5,
        "allowlist_rules_per_sandbox": 5,
        "seed_sandboxes": 250,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 0,
    },
    "allowlist_fat": {
        "description": "100% allowlist with 20 rules/sandbox (hydrate + JSON size stress).",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 12.0,
        "allowlist_fraction": 1.0,
        "allowlist_rules_per_sandbox": 20,
        "seed_sandboxes": 250,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 0,
    },
    "list_scale": {
        "description": "Larger seed (500) stressing keyset page + decode volume.",
        "primary": "sandboxes_list_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 12.0,
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 500,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 0,
    },
    "create": {
        "description": "POST /sandboxes create path emphasis (still runs full suite metrics).",
        "primary": "sandboxes_create_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 5.0,
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 100,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 0,
    },
    "ttft": {
        "description": "Dry-run sandbox TTFT (provision + first command output).",
        "primary": "ttft_total_p95_ms",
        "direction": "minimize",
        "noise_threshold_ms": 15.0,
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 50,
        "requests": 100,
        "concurrency": 10,
        "runs": 3,
        "ttft_runs": 15,
    },
    "full": {
        "description": "Full suite with more TTFT samples for claim-path work.",
        "primary": "budget_normalized_p95_pct",
        "direction": "minimize",
        "noise_threshold_ms": 0.5,  # percent points when primary is budget_normalized
        "allowlist_fraction": 0.0,
        "allowlist_rules_per_sandbox": 0,
        "seed_sandboxes": 250,
        "requests": 300,
        "concurrency": 25,
        "runs": 5,
        "ttft_runs": 15,
    },
}

# Scenarios used by matrix when --quick is set (cheap discovery loop).
QUICK_SCENARIOS: Final[list[str]] = [
    "smoke",
    "default",
    "allowlist",
    "create",
]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def median(values: list[float]) -> float:
    return float(statistics.median(values))


def stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return float(statistics.pstdev(values))


def summarize_samples(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "median": median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
        "range": ordered[-1] - ordered[0],
        "stddev": stddev(ordered),
        "n": float(len(ordered)),
    }


def opportunity_score(
    primary_median: float,
    noise_threshold: float,
    sample_range: float,
    *,
    direction: str = "minimize",
) -> float:
    """Higher = better candidate for optimization work.

    score = headroom_proxy / noise * stability
    - headroom_proxy: absolute median latency (or budget % for normalized metrics)
    - stability: 1 when range <= 2*noise, else 2*noise/range (penalize noisy)
    """
    del direction  # minimize-only for now; maximize would invert headroom
    noise = max(float(noise_threshold), 1e-9)
    stability = 1.0
    if sample_range > 2.0 * noise:
        stability = (2.0 * noise) / sample_range
    return float(primary_median) / noise * stability


# ---------------------------------------------------------------------------
# Binaries / measurement
# ---------------------------------------------------------------------------

def profile_dir(profile: str) -> Path:
    return ROOT / "target" / profile


def ensure_bins(profile: str, bin_root: Path | None = None) -> dict[str, Path]:
    root = bin_root or profile_dir(profile)
    bins = {
        "api": root / "sandboxwich-api",
        "worker": root / "sandboxwich-worker",
        "bench": root / "sandboxwich-bench",
    }
    if all(path.is_file() for path in bins.values()):
        return bins
    if bin_root is not None:
        missing = [name for name, path in bins.items() if not path.is_file()]
        raise FileNotFoundError(f"missing binaries in {bin_root}: {missing}")
    cmd = [
        "cargo",
        "build",
        "--locked",
        "-p",
        "sandboxwich-api",
        "-p",
        "sandboxwich-worker",
        "-p",
        "sandboxwich-bench",
    ]
    if profile == "release":
        cmd.append("--release")
    subprocess.run(cmd, cwd=ROOT, check=True)
    return bins


def run_scenario_once(
    scenario: dict[str, Any],
    bins: dict[str, Path],
) -> dict[str, float | int]:
    """Run sandboxwich-bench all once and parse metrics."""
    rules = int(scenario["allowlist_rules_per_sandbox"])
    if float(scenario["allowlist_fraction"]) > 0 and rules < 1:
        rules = 1
    command = [
        str(bins["bench"]),
        "all",
        "--api-bin",
        str(bins["api"]),
        "--worker-bin",
        str(bins["worker"]),
        "--runs",
        str(scenario["runs"]),
        "--ttft-runs",
        str(scenario["ttft_runs"]),
        "--requests",
        str(scenario["requests"]),
        "--concurrency",
        str(scenario["concurrency"]),
        "--seed-sandboxes",
        str(scenario["seed_sandboxes"]),
        "--allowlist-fraction",
        str(scenario["allowlist_fraction"]),
        "--allowlist-rules-per-sandbox",
        str(rules),
    ]

    env = os.environ.copy()
    env["SANDBOXWICH_ALLOW_INSECURE_NO_AUTH"] = "true"
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wall = time.perf_counter() - started
    if completed.returncode != 0:
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        raise RuntimeError(f"benchmark exited {completed.returncode}")
    if scenario["ttft_runs"] == 0:
        metrics = parse_report_optional_ttft(completed.stdout, wall)
    else:
        metrics = perf_evaluate.parse_report(completed.stdout, wall)
    if int(metrics.get("request_failures", 1)) != 0:
        raise RuntimeError(
            f"request_failures={metrics.get('request_failures')} (must be 0)"
        )
    if int(metrics.get("benchmark_completed", 0)) != 1:
        raise RuntimeError("benchmark_completed != 1")
    return metrics


def parse_report_optional_ttft(report: str, wall_seconds: float) -> dict[str, float | int]:
    """Like perf_evaluate.parse_report but TTFT rows optional when omitted."""
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
        cells = perf_evaluate.table_cells(line)
        if cells[0] in {"requests", "phase"} or cells[0].startswith("---"):
            continue

        http_definition = perf_evaluate.HTTP_SECTIONS.get(section)
        if section.startswith(perf_evaluate.POST_SECTION_PREFIX):
            http_definition = (
                perf_evaluate.POST_METRIC_PREFIX,
                perf_evaluate.POST_P95_BUDGET_MS,
            )
        if http_definition is not None:
            if len(cells) != 9 or not cells[0].isdigit() or not cells[1].isdigit():
                raise perf_evaluate.ReportError(
                    f"line {line_number}: malformed HTTP row in section {section!r}"
                )
            prefix, p95_budget_ms = http_definition
            if prefix in seen_http:
                raise perf_evaluate.ReportError(f"duplicate HTTP row for {section!r}")
            seen_http.add(prefix)
            failures = int(cells[1])
            request_failures += failures
            rps = float(cells[2])
            p95_ms = perf_evaluate.parse_milliseconds(cells[5], f"line {line_number} p95")
            metrics[f"{prefix}_p95_ms"] = p95_ms
            if prefix != "warm_startup":
                metrics[f"{prefix}_rps"] = rps
            normalized_p95.append(p95_ms / p95_budget_ms)
            continue

        if section == perf_evaluate.TTFT_SECTION and cells[0] in perf_evaluate.TTFT_ROWS:
            if len(cells) != 8 or not cells[1].isdigit():
                raise perf_evaluate.ReportError(
                    f"line {line_number}: malformed TTFT row {cells[0]!r}"
                )
            prefix = perf_evaluate.TTFT_ROWS[cells[0]]
            if prefix in seen_ttft:
                raise perf_evaluate.ReportError(f"duplicate TTFT row {cells[0]!r}")
            seen_ttft.add(prefix)
            p95_ms = perf_evaluate.parse_milliseconds(cells[4], f"line {line_number} p95")
            metrics[f"{prefix}_p95_ms"] = p95_ms
            if prefix == "ttft_total":
                normalized_p95.append(p95_ms / perf_evaluate.TTFT_P95_BUDGET_MS)

    expected_http = {definition[0] for definition in perf_evaluate.HTTP_SECTIONS.values()}
    expected_http.add(perf_evaluate.POST_METRIC_PREFIX)
    missing_http = sorted(expected_http - seen_http)
    if missing_http:
        raise perf_evaluate.ReportError(f"incomplete report: missing HTTP={missing_http}")

    metrics["request_failures"] = request_failures
    metrics["benchmark_completed"] = 1
    metrics["benchmark_wall_seconds"] = round(wall_seconds, 6)
    if normalized_p95:
        metrics["budget_normalized_p95_pct"] = round(
            sum(normalized_p95) * 100.0 / len(normalized_p95), 6
        )
    return metrics


def latency_keys_from_metrics(metrics: dict[str, Any]) -> list[str]:
    keys = [
        key
        for key, value in metrics.items()
        if isinstance(value, (int, float))
        and (key.endswith(LATENCY_SUFFIX) or key == "budget_normalized_p95_pct")
    ]
    return sorted(keys)


def aggregate_metric_across_runs(
    samples: list[dict[str, float | int]],
    metric: str,
) -> dict[str, float] | None:
    values: list[float] = []
    for sample in samples:
        if metric not in sample:
            continue
        values.append(float(sample[metric]))
    if not values:
        return None
    return summarize_samples(values)


def bottleneck_rank(
    samples: list[dict[str, float | int]],
    *,
    noise_default_ms: float = 5.0,
) -> list[dict[str, Any]]:
    """Rank latency metrics by absolute median (highest first)."""
    if not samples:
        return []
    keys: set[str] = set()
    for sample in samples:
        keys.update(latency_keys_from_metrics(sample))
    ranked: list[dict[str, Any]] = []
    for key in keys:
        summary = aggregate_metric_across_runs(samples, key)
        if summary is None:
            continue
        budget = BUDGETS_MS.get(key)
        budget_pct = None
        if budget and budget > 0 and key != "budget_normalized_p95_pct":
            budget_pct = round(100.0 * summary["median"] / budget, 4)
        noise = noise_default_ms
        if key == "budget_normalized_p95_pct":
            noise = 0.5
        score = opportunity_score(
            summary["median"],
            noise,
            summary["range"],
        )
        ranked.append(
            {
                "metric": key,
                "median": summary["median"],
                "range": summary["range"],
                "stddev": summary["stddev"],
                "budget_ms": budget,
                "budget_pct": budget_pct,
                "opportunity_score": round(score, 4),
                "noisy": summary["range"] > 2.0 * noise,
            }
        )
    ranked.sort(key=lambda row: row["median"], reverse=True)
    return ranked


def measure_repeats(
    scenario_name: str,
    profile: str,
    repeats: int,
    bins: dict[str, Path] | None = None,
) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_name]
    bins = bins or ensure_bins(profile)
    samples: list[dict[str, float | int]] = []
    primary_values: list[float] = []
    primary = scenario["primary"]
    for index in range(1, repeats + 1):
        metrics = run_scenario_once(scenario, bins)
        if primary not in metrics:
            raise RuntimeError(f"primary metric {primary!r} missing from {metrics.keys()}")
        primary_values.append(float(metrics[primary]))
        samples.append(metrics)
        print(
            f"  run {index}/{repeats}: {primary}={metrics[primary]} "
            f"list_rps={metrics.get('sandboxes_list_rps', 'n/a')} "
            f"create_p95={metrics.get('sandboxes_create_p95_ms', 'n/a')} "
            f"fail={metrics['request_failures']}",
            file=sys.stderr,
        )
    primary_summary = summarize_samples(primary_values)
    bottlenecks = bottleneck_rank(samples, noise_default_ms=float(scenario["noise_threshold_ms"]))
    score = opportunity_score(
        primary_summary["median"],
        float(scenario["noise_threshold_ms"]),
        primary_summary["range"],
        direction=str(scenario["direction"]),
    )
    return {
        "kind": "measure",
        "scenario": scenario_name,
        "description": scenario["description"],
        "profile": profile,
        "primary": primary,
        "direction": scenario["direction"],
        "noise_threshold": scenario["noise_threshold_ms"],
        "primary_samples": primary_values,
        "primary_summary": primary_summary,
        "opportunity_score": round(score, 4),
        "bottlenecks": bottlenecks,
        "runs": samples,
    }


def ab_pairs(
    scenario_name: str,
    baseline_bins: dict[str, Path],
    candidate_bins: dict[str, Path],
    pairs: int,
) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_name]
    primary = scenario["primary"]
    noise = float(scenario["noise_threshold_ms"])
    base_samples: list[float] = []
    cand_samples: list[float] = []
    pair_deltas: list[float] = []
    pair_details: list[dict[str, Any]] = []
    base_full: list[dict[str, float | int]] = []
    cand_full: list[dict[str, float | int]] = []

    for index in range(1, pairs + 1):
        base_metrics = run_scenario_once(scenario, baseline_bins)
        cand_metrics = run_scenario_once(scenario, candidate_bins)
        b = float(base_metrics[primary])
        c = float(cand_metrics[primary])
        delta = c - b
        base_samples.append(b)
        cand_samples.append(c)
        pair_deltas.append(delta)
        base_full.append(base_metrics)
        cand_full.append(cand_metrics)
        pair_details.append(
            {
                "pair": index,
                "baseline": b,
                "candidate": c,
                "delta": delta,
                "baseline_list_rps": base_metrics.get("sandboxes_list_rps"),
                "candidate_list_rps": cand_metrics.get("sandboxes_list_rps"),
            }
        )
        print(
            f"  pair {index}/{pairs}: base={b:.3f} cand={c:.3f} delta={delta:+.3f}",
            file=sys.stderr,
        )

    base_med = median(base_samples)
    cand_med = median(cand_samples)
    med_delta = cand_med - base_med
    pair_med_delta = median(pair_deltas)
    wins = sum(
        1
        for b, c in zip(base_samples, cand_samples)
        if (c < b if scenario["direction"] == "minimize" else c > b)
    )
    clears_noise = abs(med_delta) >= noise
    majority = wins > pairs / 2
    improved = med_delta < 0 if scenario["direction"] == "minimize" else med_delta > 0
    if improved and clears_noise and majority:
        verdict = "KEEP"
    elif not clears_noise:
        verdict = "NOISY"
    else:
        verdict = "REJECT"

    # Secondary metrics: which other p95s moved with the candidate?
    secondary: list[dict[str, Any]] = []
    metric_keys: set[str] = set()
    for sample in base_full + cand_full:
        metric_keys.update(latency_keys_from_metrics(sample))
    for key in sorted(metric_keys):
        b_sum = aggregate_metric_across_runs(base_full, key)
        c_sum = aggregate_metric_across_runs(cand_full, key)
        if b_sum is None or c_sum is None:
            continue
        delta = c_sum["median"] - b_sum["median"]
        key_noise = noise if key == primary else 5.0
        if key == "budget_normalized_p95_pct":
            key_noise = 0.5
        if abs(delta) < key_noise:
            key_verdict = "NOISY"
        elif delta < 0:
            key_verdict = "KEEP"
        else:
            key_verdict = "REGRESS"
        secondary.append(
            {
                "metric": key,
                "baseline_median": b_sum["median"],
                "candidate_median": c_sum["median"],
                "delta": delta,
                "verdict": key_verdict,
            }
        )
    secondary.sort(key=lambda row: abs(row["delta"]), reverse=True)

    return {
        "kind": "ab",
        "scenario": scenario_name,
        "primary": primary,
        "noise_threshold": noise,
        "pairs": pairs,
        "baseline_samples": base_samples,
        "candidate_samples": cand_samples,
        "baseline_median": base_med,
        "candidate_median": cand_med,
        "median_delta": med_delta,
        "pair_delta_median": pair_med_delta,
        "pair_deltas": pair_deltas,
        "pair_wins": wins,
        "verdict": verdict,
        "pair_details": pair_details,
        "baseline_summary": summarize_samples(base_samples),
        "candidate_summary": summarize_samples(cand_samples),
        "secondary_metrics": secondary,
    }


def build_ref(ref: str, profile: str) -> dict[str, Path]:
    """Build binaries for a git ref into an isolated temp directory via worktree."""
    work = Path(tempfile.mkdtemp(prefix="sw-perf-"))
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(work), ref],
        cwd=ROOT,
        check=True,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )
    target = work / "target" / profile
    cmd = [
        "cargo",
        "build",
        "--locked",
        "-p",
        "sandboxwich-api",
        "-p",
        "sandboxwich-worker",
        "-p",
        "sandboxwich-bench",
    ]
    if profile == "release":
        cmd.append("--release")
    subprocess.run(cmd, cwd=work, check=True, stdout=sys.stderr, stderr=sys.stderr)
    return {
        "api": target / "sandboxwich-api",
        "worker": target / "sandboxwich-worker",
        "bench": target / "sandboxwich-bench",
        "_worktree": work,  # type: ignore[dict-item]
    }


def write_run(payload: dict[str, Any], label: str) -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = RUNS_DIR / f"{stamp}-{label}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    # Also refresh a stable "latest" symlink-style copy for tooling.
    latest = RUNS_DIR / f"latest-{label.split('-')[0]}.json"
    latest.write_text(path.read_text())
    return path


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def resolve_run_path(raw: str) -> Path:
    path = Path(raw)
    if path.is_file():
        return path
    candidate = RUNS_DIR / raw
    if candidate.is_file():
        return candidate
    # Allow latest-* shorthand
    latest = RUNS_DIR / f"latest-{raw}.json"
    if latest.is_file():
        return latest
    raise FileNotFoundError(f"run file not found: {raw}")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_scenarios(_: argparse.Namespace) -> int:
    for name, scenario in SCENARIOS.items():
        print(
            f"{name:16} primary={scenario['primary']:28} "
            f"noise={scenario['noise_threshold_ms']:<6} {scenario['description']}"
        )
    return 0


def cmd_measure(args: argparse.Namespace) -> int:
    if args.scenario not in SCENARIOS:
        print(f"unknown scenario {args.scenario!r}", file=sys.stderr)
        return 2
    print(
        f"measure scenario={args.scenario} profile={args.profile} repeats={args.repeats}",
        file=sys.stderr,
    )
    result = measure_repeats(args.scenario, args.profile, args.repeats)
    path = write_run(result, f"measure-{args.scenario}")
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"wrote {path}", file=sys.stderr)
    primary = result["primary"]
    summary = result["primary_summary"]
    print(
        f"VERDICT measure: {primary} median={summary['median']:.3f} "
        f"range={summary['range']:.3f} stddev={summary['stddev']:.3f} "
        f"opportunity={result['opportunity_score']:.2f} "
        f"noise_threshold={result['noise_threshold']}",
        file=sys.stderr,
    )
    print("Top bottlenecks (absolute median p95):", file=sys.stderr)
    for row in result["bottlenecks"][:6]:
        bp = f" budget={row['budget_pct']:.2f}%" if row.get("budget_pct") is not None else ""
        flag = " NOISY" if row["noisy"] else ""
        print(
            f"  {row['metric']:32} median={row['median']:.3f} "
            f"opp={row['opportunity_score']:.2f}{bp}{flag}",
            file=sys.stderr,
        )
    return 0


def cmd_ab(args: argparse.Namespace) -> int:
    if args.scenario not in SCENARIOS:
        print(f"unknown scenario {args.scenario!r}", file=sys.stderr)
        return 2
    baseline_bins: dict[str, Path]
    candidate_bins: dict[str, Path]
    worktrees: list[Path] = []

    try:
        if args.baseline_ref:
            print(f"building baseline ref {args.baseline_ref}...", file=sys.stderr)
            baseline_bins = build_ref(args.baseline_ref, args.profile)
            worktrees.append(Path(str(baseline_bins.pop("_worktree"))))
        else:
            baseline_bins = {
                "api": Path(args.baseline_api),
                "worker": Path(args.baseline_worker),
                "bench": Path(args.baseline_bench),
            }
        if args.candidate_ref:
            print(f"building candidate ref {args.candidate_ref}...", file=sys.stderr)
            candidate_bins = build_ref(args.candidate_ref, args.profile)
            worktrees.append(Path(str(candidate_bins.pop("_worktree"))))
        elif args.candidate_api:
            candidate_bins = {
                "api": Path(args.candidate_api),
                "worker": Path(args.candidate_worker),
                "bench": Path(args.candidate_bench),
            }
        else:
            candidate_bins = ensure_bins(args.profile)

        print(
            f"ab scenario={args.scenario} pairs={args.pairs} profile={args.profile}",
            file=sys.stderr,
        )
        result = ab_pairs(args.scenario, baseline_bins, candidate_bins, args.pairs)
        result["baseline_ref"] = args.baseline_ref
        result["candidate_ref"] = args.candidate_ref
        path = write_run(result, f"ab-{args.scenario}")
        print(json.dumps(result, indent=2, sort_keys=True))
        print(f"wrote {path}", file=sys.stderr)
        print(
            f"VERDICT {result['verdict']}: median_delta={result['median_delta']:+.3f} "
            f"pair_delta_median={result['pair_delta_median']:+.3f} "
            f"wins={result['pair_wins']}/{args.pairs} "
            f"noise={result['noise_threshold']}",
            file=sys.stderr,
        )
        if result.get("secondary_metrics"):
            print("Secondary metric deltas (largest |delta| first):", file=sys.stderr)
            for row in result["secondary_metrics"][:8]:
                print(
                    f"  {row['verdict']:7} {row['metric']:32} "
                    f"{row['baseline_median']:.3f} -> {row['candidate_median']:.3f} "
                    f"({row['delta']:+.3f})",
                    file=sys.stderr,
                )
        if args.hypothesis:
            append_ledger(
                {
                    "hypothesis": args.hypothesis,
                    "scenario": args.scenario,
                    "verdict": result["verdict"],
                    "median_delta": result["median_delta"],
                    "baseline_ref": args.baseline_ref,
                    "candidate_ref": args.candidate_ref,
                    "run": str(path),
                }
            )
            print(f"ledger += {args.hypothesis!r} -> {result['verdict']}", file=sys.stderr)
        return 0 if result["verdict"] != "REJECT" else 3
    finally:
        for work in worktrees:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(work)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def cmd_matrix(args: argparse.Namespace) -> int:
    names = list(args.scenarios) if args.scenarios else (
        QUICK_SCENARIOS if args.quick else list(SCENARIOS.keys())
    )
    ranking: list[dict[str, Any]] = []
    for name in names:
        if name not in SCENARIOS:
            print(f"unknown scenario {name!r}", file=sys.stderr)
            return 2
        print(f"=== matrix scenario {name} ===", file=sys.stderr)
        result = measure_repeats(name, args.profile, args.repeats)
        write_run(result, f"measure-{name}")
        top = result["bottlenecks"][:3] if result.get("bottlenecks") else []
        ranking.append(
            {
                "scenario": name,
                "primary": result["primary"],
                "median": result["primary_summary"]["median"],
                "range": result["primary_summary"]["range"],
                "stddev": result["primary_summary"]["stddev"],
                "noise_threshold": result["noise_threshold"],
                "opportunity_score": result["opportunity_score"],
                "noisy": result["primary_summary"]["range"]
                > 2 * float(result["noise_threshold"]),
                "top_bottlenecks": [
                    {"metric": b["metric"], "median": b["median"]} for b in top
                ],
            }
        )
    ranking.sort(key=lambda row: row["opportunity_score"], reverse=True)
    payload = {
        "kind": "matrix",
        "profile": args.profile,
        "repeats": args.repeats,
        "scenarios": names,
        "ranking": ranking,
        "hint": (
            "Sort key is opportunity_score = median/noise * stability. "
            "Work the top non-NOISY row next; confirm with ab --pairs 5 --profile release."
        ),
    }
    path = write_run(payload, "matrix")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"wrote {path}", file=sys.stderr)
    print("\nRanked opportunity (highest opportunity_score first):", file=sys.stderr)
    for row in ranking:
        flag = " NOISY" if row["noisy"] else ""
        print(
            f"  {row['scenario']:16} {row['primary']:28} "
            f"median={row['median']:.3f} opp={row['opportunity_score']:.2f} "
            f"range={row['range']:.3f}{flag}",
            file=sys.stderr,
        )
        for bot in row.get("top_bottlenecks") or []:
            print(f"      bottleneck {bot['metric']}={bot['median']:.3f}", file=sys.stderr)
    if ranking:
        best = ranking[0]
        print(
            f"\nNEXT: implement a change, then:\n"
            f"  python3 scripts/perf-harness.py ab --baseline-ref origin/main "
            f"--scenario {best['scenario']} --pairs 5 --profile {args.profile} "
            f"--hypothesis 'describe the change'",
            file=sys.stderr,
        )
    return 0


def cmd_bottleneck(args: argparse.Namespace) -> int:
    path = resolve_run_path(args.run)
    payload = load_json(path)
    samples = payload.get("runs")
    if not samples and payload.get("kind") == "matrix":
        print(
            "matrix runs point at per-scenario measure files; pass a measure-*.json path",
            file=sys.stderr,
        )
        return 2
    if not samples:
        raise RuntimeError(f"no runs[] in {path}")
    noise = float(payload.get("noise_threshold", 5.0))
    ranked = bottleneck_rank(samples, noise_default_ms=noise)
    out = {
        "kind": "bottleneck",
        "source": str(path),
        "scenario": payload.get("scenario"),
        "primary": payload.get("primary"),
        "ranking": ranked,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    print(f"\nBottlenecks from {path}:", file=sys.stderr)
    for row in ranked:
        bp = f" budget={row['budget_pct']:.2f}%" if row.get("budget_pct") is not None else ""
        flag = " NOISY" if row["noisy"] else ""
        print(
            f"  {row['metric']:32} median={row['median']:.3f} "
            f"opp={row['opportunity_score']:.2f}{bp}{flag}",
            file=sys.stderr,
        )
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    before = load_json(resolve_run_path(args.before))
    after = load_json(resolve_run_path(args.after))
    noise = float(args.noise)

    def extract_medians(payload: dict[str, Any]) -> dict[str, float]:
        if payload.get("kind") == "ab":
            # Compare candidate vs baseline inside one ab file is different path.
            return {
                "primary_baseline": float(payload["baseline_median"]),
                "primary_candidate": float(payload["candidate_median"]),
            }
        samples = payload.get("runs")
        if samples:
            medians: dict[str, float] = {}
            for key in latency_keys_from_metrics(samples[0]):
                summary = aggregate_metric_across_runs(samples, key)
                if summary:
                    medians[key] = summary["median"]
            if payload.get("primary") and payload.get("primary_summary"):
                medians[str(payload["primary"])] = float(
                    payload["primary_summary"]["median"]
                )
            return medians
        if payload.get("kind") == "matrix":
            return {
                f"scenario:{row['scenario']}": float(row["median"])
                for row in payload.get("ranking", [])
            }
        raise RuntimeError("unsupported run shape for compare")

    b_med = extract_medians(before)
    a_med = extract_medians(after)
    keys = sorted(set(b_med) | set(a_med))
    rows: list[dict[str, Any]] = []
    for key in keys:
        if key not in b_med or key not in a_med:
            rows.append(
                {
                    "metric": key,
                    "before": b_med.get(key),
                    "after": a_med.get(key),
                    "delta": None,
                    "verdict": "MISSING",
                }
            )
            continue
        delta = a_med[key] - b_med[key]
        key_noise = noise
        if key == "budget_normalized_p95_pct" or key.endswith("_pct"):
            key_noise = min(noise, 0.5) if noise >= 0.5 else noise
        if abs(delta) < key_noise:
            verdict = "NOISY"
        elif delta < 0:
            verdict = "KEEP"
        else:
            verdict = "REGRESS"
        rows.append(
            {
                "metric": key,
                "before": b_med[key],
                "after": a_med[key],
                "delta": delta,
                "verdict": verdict,
            }
        )
    rows.sort(key=lambda row: abs(row["delta"] or 0.0), reverse=True)
    payload = {
        "kind": "compare",
        "before": str(resolve_run_path(args.before)),
        "after": str(resolve_run_path(args.after)),
        "noise": noise,
        "metrics": rows,
        "keeps": sum(1 for r in rows if r["verdict"] == "KEEP"),
        "regresses": sum(1 for r in rows if r["verdict"] == "REGRESS"),
        "noisy": sum(1 for r in rows if r["verdict"] == "NOISY"),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"compare: KEEP={payload['keeps']} REGRESS={payload['regresses']} "
        f"NOISY={payload['noisy']} noise={noise}",
        file=sys.stderr,
    )
    for row in rows:
        if row["delta"] is None:
            print(f"  {row['verdict']:8} {row['metric']}", file=sys.stderr)
            continue
        print(
            f"  {row['verdict']:8} {row['metric']:32} "
            f"{row['before']:.3f} -> {row['after']:.3f} ({row['delta']:+.3f})",
            file=sys.stderr,
        )
    return 1 if payload["regresses"] else 0


def cmd_report(args: argparse.Namespace) -> int:
    path = resolve_run_path(args.run)
    payload = load_json(path)
    kind = payload.get("kind", "unknown")
    print(f"report kind={kind} path={path}")
    if kind == "measure":
        print(f"  scenario={payload.get('scenario')} primary={payload.get('primary')}")
        s = payload.get("primary_summary") or {}
        print(
            f"  median={s.get('median')} range={s.get('range')} "
            f"opp={payload.get('opportunity_score')}"
        )
        for row in (payload.get("bottlenecks") or [])[:8]:
            print(f"  bottleneck {row['metric']}={row['median']}")
    elif kind == "ab":
        print(
            f"  scenario={payload.get('scenario')} verdict={payload.get('verdict')} "
            f"delta={payload.get('median_delta')}"
        )
        for row in (payload.get("secondary_metrics") or [])[:8]:
            print(
                f"  {row['verdict']} {row['metric']}: "
                f"{row['baseline_median']} -> {row['candidate_median']}"
            )
    elif kind == "matrix":
        for row in payload.get("ranking") or []:
            print(
                f"  {row['scenario']:16} median={row['median']:.3f} "
                f"opp={row.get('opportunity_score', 0):.2f}"
                f"{' NOISY' if row.get('noisy') else ''}"
            )
    else:
        print(json.dumps(payload, indent=2)[:2000])
    return 0


def cmd_history(_: argparse.Namespace) -> int:
    if not RUNS_DIR.is_dir():
        print("no .perf/runs yet")
        return 0
    files = sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in files[:30]:
        if path.name.startswith("latest-"):
            continue
        try:
            payload = load_json(path)
        except (OSError, json.JSONDecodeError):
            print(f"{path.name:48} (unreadable)")
            continue
        kind = payload.get("kind", "?")
        scenario = payload.get("scenario") or ""
        extra = ""
        if kind == "measure":
            s = payload.get("primary_summary") or {}
            extra = f"median={s.get('median')} opp={payload.get('opportunity_score')}"
        elif kind == "ab":
            extra = f"verdict={payload.get('verdict')} delta={payload.get('median_delta')}"
        elif kind == "matrix":
            extra = f"scenarios={len(payload.get('ranking') or [])}"
        print(f"{path.name:48} {kind:8} {scenario:16} {extra}")
    return 0


def append_ledger(entry: dict[str, Any]) -> None:
    PERF_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        **entry,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with LEDGER_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def cmd_ledger(args: argparse.Namespace) -> int:
    if args.list or not args.hypothesis:
        if not LEDGER_PATH.is_file():
            print("ledger empty")
            return 0
        for line in LEDGER_PATH.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            print(
                f"{entry.get('ts', '?'):20} {entry.get('verdict', '?'):7} "
                f"{entry.get('scenario', '?'):16} {entry.get('hypothesis', '')} "
                f"delta={entry.get('median_delta')}"
            )
        return 0
    # Manual ledger note without an ab run.
    append_ledger(
        {
            "hypothesis": args.hypothesis,
            "scenario": args.scenario or "",
            "verdict": args.verdict or "NOTE",
            "median_delta": args.delta,
            "note": args.note or "",
        }
    )
    print(f"appended hypothesis {args.hypothesis!r}", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_sc = sub.add_parser("scenarios", help="List built-in scenarios")
    p_sc.set_defaults(func=cmd_scenarios)

    p_m = sub.add_parser("measure", help="Repeat one scenario and summarize")
    p_m.add_argument("--scenario", default="default")
    p_m.add_argument("--profile", choices=["debug", "release"], default="release")
    p_m.add_argument("--repeats", type=int, default=5)
    p_m.set_defaults(func=cmd_measure)

    p_ab = sub.add_parser("ab", help="Interleaved A/B of baseline vs candidate")
    p_ab.add_argument("--scenario", default="default")
    p_ab.add_argument("--profile", choices=["debug", "release"], default="release")
    p_ab.add_argument("--pairs", type=int, default=5)
    p_ab.add_argument("--baseline-ref", default=None, help="git ref for baseline build")
    p_ab.add_argument("--candidate-ref", default=None, help="git ref for candidate build")
    p_ab.add_argument("--baseline-api", default=None)
    p_ab.add_argument("--baseline-worker", default=None)
    p_ab.add_argument("--baseline-bench", default=None)
    p_ab.add_argument("--candidate-api", default=None)
    p_ab.add_argument("--candidate-worker", default=None)
    p_ab.add_argument("--candidate-bench", default=None)
    p_ab.add_argument(
        "--hypothesis",
        default=None,
        help="Record this hypothesis + verdict into .perf/hypotheses.jsonl",
    )
    p_ab.set_defaults(func=cmd_ab)

    p_mx = sub.add_parser("matrix", help="Measure scenarios and rank opportunity")
    p_mx.add_argument("--profile", choices=["debug", "release"], default="release")
    p_mx.add_argument("--repeats", type=int, default=3)
    p_mx.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Subset of scenarios (default: all)",
    )
    p_mx.add_argument(
        "--quick",
        action="store_true",
        help="Only smoke/default/allowlist/create (faster discovery)",
    )
    p_mx.set_defaults(func=cmd_matrix)

    p_bn = sub.add_parser("bottleneck", help="Rank latency metrics inside a measure run")
    p_bn.add_argument(
        "--run",
        required=True,
        help="Path or name under .perf/runs (e.g. measure, or full path)",
    )
    p_bn.set_defaults(func=cmd_bottleneck)

    p_cmp = sub.add_parser("compare", help="Diff two measure/matrix JSON runs")
    p_cmp.add_argument("--before", required=True)
    p_cmp.add_argument("--after", required=True)
    p_cmp.add_argument(
        "--noise",
        type=float,
        default=5.0,
        help="Absolute delta below this is NOISY (default 5 ms)",
    )
    p_cmp.set_defaults(func=cmd_compare)

    p_rp = sub.add_parser("report", help="Pretty-print a saved run")
    p_rp.add_argument("--run", required=True)
    p_rp.set_defaults(func=cmd_report)

    p_hi = sub.add_parser("history", help="List recent .perf/runs files")
    p_hi.set_defaults(func=cmd_history)

    p_ld = sub.add_parser("ledger", help="Hypothesis results log")
    p_ld.add_argument("--list", action="store_true")
    p_ld.add_argument("--hypothesis", default=None)
    p_ld.add_argument("--scenario", default=None)
    p_ld.add_argument("--verdict", default=None)
    p_ld.add_argument("--delta", type=float, default=None)
    p_ld.add_argument("--note", default=None)
    p_ld.set_defaults(func=cmd_ledger)

    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (OSError, RuntimeError, subprocess.SubprocessError, perf_evaluate.ReportError) as error:
        print(f"perf-harness failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
