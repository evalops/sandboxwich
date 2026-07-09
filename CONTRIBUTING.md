# Contributing

Run the required local gates before opening a pull request:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Postgres contract tests require `SANDBOXWICH_TEST_POSTGRES_URL`. Changes to a
provider or lifecycle transition should include a contract test and, where
applicable, a disposable-cluster conformance test.

Keep commits atomic. Merge current `main` into the branch before landing and
rerun the full gate; clean textual merges do not guarantee semantic
compatibility. Never commit credentials or runtime secrets.

By contributing, you agree that your contribution is licensed under
[Apache-2.0](LICENSE).
