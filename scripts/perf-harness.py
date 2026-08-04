#!/usr/bin/env python3
"""Identify sandboxwich control-plane performance regressions and wins.

Commands
--------
  measure   Run one scenario N times; emit median/range/stddev JSON.
  ab        Interleaved A/B of two binary trees (or git refs) for one scenario.
  matrix    Run every built-in scenario once (or N times) and rank by primary metric.
  scenarios List scenario definitions.

Design goals
------------
- Fail closed: missing metrics or non-zero request_failures are hard errors.
- Noise-aware: declare a primary metric and noise threshold; A/B prints KEEP/REJECT/NOISY.
- Scenario-shaped: allowlist-heavy list, default list, create, TTFT, full suite.
- Release-first: defaults to release binaries so decode/serialize cost is real.

Examples
--------
  SANDBOXWICH_PERF_PROFILE=release python3 scripts/perf-harness.py measure --scenario allowlist
  python3 scripts/perf-harness.py ab --baseline-ref origin/main --candidate-ref HEAD \\
      --scenario allowlist --pairs 5 --profile release
  python3 scripts/perf-harness.py matrix --profile release --repeats 3
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Final


ROOT: Final = Path(__file__).resolve().parent.parent

# Reuse the existing fail-closed report parser (hyphenated filename).
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "perf_evaluate",
    Path(__file__).resolve().parent / "perf-evaluate.py",
)
assert _spec is not None and _spec.loader is not None
perf_evaluate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(perf_evaluate)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS: Final[dict[str, dict[str, Any]]] = {
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
        str(max(1, int(scenario["allowlist_rules_per_sandbox"]))
            if scenario["allowlist_fraction"] > 0
            else 0),
    ]
    # When fraction is 0, rules-per-sandbox flag still accepted (0 ok for seed path).
    if scenario["allowlist_fraction"] <= 0:
        # Rewrite last two flags to omit rules when unused — still pass 0.
        pass

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
    # TTFT-optional scenarios still parse with ttft_runs=0 — extend parser.
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
            f"fail={metrics['request_failures']}",
            file=sys.stderr,
        )
    return {
        "scenario": scenario_name,
        "description": scenario["description"],
        "profile": profile,
        "primary": primary,
        "direction": scenario["direction"],
        "noise_threshold": scenario["noise_threshold_ms"],
        "primary_samples": primary_values,
        "primary_summary": summarize_samples(primary_values),
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

    for index in range(1, pairs + 1):
        base_metrics = run_scenario_once(scenario, baseline_bins)
        cand_metrics = run_scenario_once(scenario, candidate_bins)
        b = float(base_metrics[primary])
        c = float(cand_metrics[primary])
        delta = c - b
        base_samples.append(b)
        cand_samples.append(c)
        pair_deltas.append(delta)
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
    # Verdict: KEEP if median-of-medians clears noise and candidate wins majority of pairs.
    clears_noise = abs(med_delta) >= noise
    majority = wins > pairs / 2
    improved = med_delta < 0 if scenario["direction"] == "minimize" else med_delta > 0
    if improved and clears_noise and majority:
        verdict = "KEEP"
    elif not clears_noise:
        verdict = "NOISY"
    else:
        verdict = "REJECT"

    return {
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
    }


def build_ref(ref: str, profile: str) -> dict[str, Path]:
    """Build binaries for a git ref into an isolated temp directory via worktree."""
    work = Path(tempfile.mkdtemp(prefix="sw-perf-"))
    # detached worktree
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
    out_dir = ROOT / ".perf" / "runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = out_dir / f"{stamp}-{label}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_scenarios(_: argparse.Namespace) -> int:
    for name, scenario in SCENARIOS.items():
        print(f"{name:16} primary={scenario['primary']:28} {scenario['description']}")
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
        f"noise_threshold={result['noise_threshold']}",
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
            # Default candidate: current tree build.
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
    ranking: list[dict[str, Any]] = []
    for name in args.scenarios or list(SCENARIOS.keys()):
        print(f"=== matrix scenario {name} ===", file=sys.stderr)
        result = measure_repeats(name, args.profile, args.repeats)
        ranking.append(
            {
                "scenario": name,
                "primary": result["primary"],
                "median": result["primary_summary"]["median"],
                "range": result["primary_summary"]["range"],
                "stddev": result["primary_summary"]["stddev"],
                "noise_threshold": result["noise_threshold"],
                "noisy": result["primary_summary"]["range"]
                > 2 * float(result["noise_threshold"]),
            }
        )
    # Sort by absolute median for minimize metrics (higher = more room to improve)
    ranking.sort(key=lambda row: row["median"], reverse=True)
    payload = {
        "profile": args.profile,
        "repeats": args.repeats,
        "ranking": ranking,
        "hint": (
            "Scenarios with high median AND range <= 2*noise are the best targets. "
            "NOISY scenarios need interleaved A/B before trusting a candidate."
        ),
    }
    path = write_run(payload, "matrix")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"wrote {path}", file=sys.stderr)
    print("\nRanked opportunity (highest primary median first):", file=sys.stderr)
    for row in ranking:
        flag = " NOISY" if row["noisy"] else ""
        print(
            f"  {row['scenario']:16} {row['primary']:28} "
            f"median={row['median']:.3f} range={row['range']:.3f}{flag}",
            file=sys.stderr,
        )
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
    p_ab.set_defaults(func=cmd_ab)

    p_mx = sub.add_parser("matrix", help="Measure all scenarios and rank opportunity")
    p_mx.add_argument("--profile", choices=["debug", "release"], default="release")
    p_mx.add_argument("--repeats", type=int, default=3)
    p_mx.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Subset of scenarios (default: all)",
    )
    p_mx.set_defaults(func=cmd_matrix)

    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (OSError, RuntimeError, subprocess.SubprocessError, perf_evaluate.ReportError) as error:
        print(f"perf-harness failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
