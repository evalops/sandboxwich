# Repository rules

The `main` branch accepts changes through pull requests and merge commits. Its
ruleset requires the Rust, Clippy, dependency audit, Rust 1.95, service image,
and runtime image jobs as pull request checks. Kubernetes conformance runs on
the push to `main` after a pull request merges and is intentionally not a
required pull request check.

The source-controlled payload is `.github/rulesets/main.json`. Apply it with a
repository administration token after the payload's pull request has merged:

```sh
ruleset_id="$(gh api repos/evalops/sandboxwich/rulesets --jq '.[] | select(.name == "main") | .id')"
if test -n "${ruleset_id}"; then
  gh api --method PUT "repos/evalops/sandboxwich/rulesets/${ruleset_id}" \
    --input .github/rulesets/main.json
else
  gh api --method POST repos/evalops/sandboxwich/rulesets \
    --input .github/rulesets/main.json
fi
```

Run `python3 scripts/test-repository-rules.py` before applying changes. The
test prevents a required context from being renamed or made path-conditional,
which would leave otherwise valid pull requests permanently pending.
