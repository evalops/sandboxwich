# Control-plane performance harness

Use this when you want a **fail-closed, noise-aware** measurement of a change
instead of eyeballing one debug `perf-evaluate` run.

Artifacts land in `.perf/runs/` (gitignored). Hypothesis results go to
`.perf/hypotheses.jsonl`.

## Commands

```bash
# List scenarios
python3 scripts/perf-harness.py scenarios

# Fast discovery matrix (smoke + default + allowlist + create)
python3 scripts/perf-harness.py matrix --quick --profile release --repeats 3

# Full matrix (all scenarios)
python3 scripts/perf-harness.py matrix --profile release --repeats 3

# Measure one scenario; prints bottleneck ranking of every p95 metric
python3 scripts/perf-harness.py measure --scenario allowlist --profile release --repeats 5

# Rank latency metrics inside a saved measure run
python3 scripts/perf-harness.py bottleneck --run measure

# Interleaved A/B: build main vs working tree; records secondary metric deltas
python3 scripts/perf-harness.py ab \
  --baseline-ref origin/main \
  --candidate-ref HEAD \
  --scenario allowlist \
  --pairs 5 \
  --profile release \
  --hypothesis "batch allowlist IN query"

# Diff two measure/matrix JSON files (KEEP / REGRESS / NOISY per metric)
python3 scripts/perf-harness.py compare --before .perf/runs/a.json --after .perf/runs/b.json --noise 5

# Inspect a saved run
python3 scripts/perf-harness.py report --run measure
python3 scripts/perf-harness.py history
python3 scripts/perf-harness.py ledger --list
```

## Verdicts (A/B)

| Verdict | Meaning |
|---------|---------|
| `KEEP` | Median delta clears the scenario noise threshold **and** candidate wins a majority of pairs |
| `NOISY` | Median delta is below the noise threshold |
| `REJECT` | Median moves the wrong way past noise, or fails majority pairs |

`compare` uses `KEEP` / `REGRESS` / `NOISY` / `MISSING` per metric.

## Opportunity score

```
opportunity_score = median / noise_threshold * stability
```

`stability` is `1` when `range <= 2 * noise`, else `2 * noise / range`.

Matrix ranks by this score (highest first). Work the top non-NOISY scenario next.

## Scenarios

| Name | Primary | Notes |
|------|---------|--------|
| `smoke` | list p95 | Small seed; fast local iteration |
| `default` | list p95 | deny_all seed, full suite + TTFT |
| `allowlist` | list p95 | 100% allowlist seed with 5 rules; batch hydration |
| `allowlist_mixed` | list p95 | 50% allowlist |
| `allowlist_fat` | list p95 | 100% allowlist, 20 rules/sandbox |
| `list_scale` | list p95 | 500 sandboxes seed |
| `create` | create p95 | create-weighted |
| `ttft` | TTFT total p95 | dry-run k8s worker |
| `full` | budget-normalized % | broad regression surface |

## Workflow for finding wins

1. `matrix --quick --profile release` — rank scenarios by opportunity score.
2. `measure --scenario <top>` then `bottleneck --run measure` — see which p95 dominates.
3. Implement a change on a branch.
4. `ab --baseline-ref origin/main --scenario <name> --pairs 5 --profile release --hypothesis '...'`
5. Only keep if verdict is `KEEP`. Secondary metric rows show collateral moves.
6. `ledger --list` reviews what you already tried.

Example finding (debug matrix): allowlist list p95 ~59 ms vs default ~49 ms.
That gap is allowlist hydration. Correlated per-row JSON aggregates were not
faster than a single batched `IN` query under a 100% allowlist seed.

## Bench flags used under the hood

`sandboxwich-bench all` / `seed` accept:

- `--allowlist-fraction 0.0..1.0`
- `--allowlist-rules-per-sandbox N`
