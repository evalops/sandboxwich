# Control-plane performance harness

Use this when you want a **fail-closed, noise-aware** measurement of a change
instead of eyeballing one debug `perf-evaluate` run.

## Commands

```bash
# List scenarios
python3 scripts/perf-harness.py scenarios

# Measure one scenario (release binaries; builds if missing)
python3 scripts/perf-harness.py measure --scenario allowlist --profile release --repeats 5

# Interleaved A/B: build main vs working tree
python3 scripts/perf-harness.py ab \
  --baseline-ref origin/main \
  --candidate-ref HEAD \
  --scenario allowlist \
  --pairs 5 \
  --profile release

# Rank opportunity across scenarios
python3 scripts/perf-harness.py matrix --profile release --repeats 3
```

## Verdicts (A/B)

| Verdict | Meaning |
|---------|---------|
| `KEEP` | Median delta clears the scenario noise threshold **and** candidate wins a majority of pairs |
| `NOISY` | Median delta is below the noise threshold |
| `REJECT` | Median moves the wrong way past noise, or fails majority pairs |

## Scenarios

| Name | Primary | Notes |
|------|---------|--------|
| `default` | list p95 | deny_all seed, full suite + TTFT |
| `allowlist` | list p95 | 100% allowlist seed with 5 rules (JSON-fold path) |
| `allowlist_mixed` | list p95 | 50% allowlist |
| `create` | create p95 | create-weighted |
| `ttft` | TTFT total p95 | dry-run k8s worker |
| `full` | budget-normalized % | broad regression surface |

## Artifacts

JSON runs land in `.perf/runs/` (gitignored if not already).

## Bench flags used under the hood

`sandboxwich-bench all` now accepts:

- `--allowlist-fraction 0.0..1.0`
- `--allowlist-rules-per-sandbox N`
