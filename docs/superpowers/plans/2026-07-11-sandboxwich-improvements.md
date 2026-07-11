# Sandboxwich Improvement Wave Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the eight approved sandboxwich improvements as independently validated and merged pull requests.

**Architecture:** Security boundaries land before new network reachability. Repository controls and immutable artifacts land as isolated operational changes. Contract, telemetry, refactor, and maturity work retain the existing public API unless their task explicitly versions a change.

**Tech Stack:** Rust 1.95, Axum, SQLx SQLite/PostgreSQL, Kubernetes/kind, Cilium policy CRDs, Prometheus, OpenAPI/utoipa, GitHub Actions and repository rulesets.

## Global Constraints

- Preserve `unsafe_code = "forbid"`.
- Never serialize, persist, print, or pass raw credentials on argv.
- Use merge commits and never force-push a published branch.
- Merge current `main` into each branch and run the full gate before landing.
- Use test-first red-green cycles for behavior changes.

---

### Task 1: Sandbox-bound guest authorization

**Files:** Create a guest-principal migration and `crates/sandboxwich-api/src/guest_auth.rs`; modify API auth/routes/lease handlers, worker provisioning, agent client, core contracts, and contract tests.

**Interfaces:** Produce a guest token principal bound to tenant, worker, sandbox, allowed job kinds, and expiry; consume it on guest lease and health routes.

- [ ] Add failing SQLite and PostgreSQL HTTP tests for wrong sandbox, wrong kind, expiry, revocation, renewal, completion, output append, and health update.
- [ ] Run the focused contract tests and confirm authorization failures are absent or incorrect.
- [ ] Add token minting, hash storage, authentication middleware, handler authorization, Secret delivery, and teardown revocation.
- [ ] Run focused tests, the canary-token sweep, and the full repository gate.
- [ ] Commit, push, create the PR, merge current `main`, reverify, wait for CI/review, and merge with a merge commit.

### Task 2: Provider-neutral FQDN egress

**Files:** Modify core network policy types, API validation, worker provider capabilities/manifests/config, Kubernetes conformance, and capability docs.

**Interfaces:** Add an explicit Kubernetes FQDN backend enum; Cilium renders `CiliumNetworkPolicy` `toFQDNs`; the standard backend rejects host rules.

- [ ] Add failing provider and API tests for backend capability, normalized hosts, wildcard rejection, mixed CIDR/host rules, and unsupported-provider errors.
- [ ] Run focused tests and confirm host rules fail for the intended missing capability.
- [ ] Implement Cilium manifest rendering and fail-closed validation; extend kind conformance with Cilium and DNS allow/deny probes.
- [ ] Run focused tests, kind conformance, and the full repository gate.
- [ ] Commit, push, create the PR closing #133, integrate `main`, reverify, wait for CI/review, and merge.

### Task 3: Main-branch ruleset

**Files:** Modify CI job names/concurrency if needed; add `docs/repository-rules.md` and a checked-in ruleset JSON fixture.

**Interfaces:** Require the exact stable GitHub check contexts produced on pull requests.

- [ ] Add a script test that compares ruleset required contexts with workflow job names.
- [ ] Run it and confirm it fails before the ruleset fixture exists.
- [ ] Add the fixture, docs, and validator; merge its PR.
- [ ] Apply the ruleset with `gh api`, verify enforcement through readback, and test that direct updates are rejected.

### Task 4: Immutable image promotion

**Files:** Modify Kubernetes manifests and container workflow; add Kustomize base/overlay files and digest validation tests.

**Interfaces:** Accept full `image@sha256:<64 hex>` references and require the migration/API pair to share the API digest.

- [ ] Add a failing shell validator test for tags, malformed digests, and mismatched API digests.
- [ ] Implement Kustomize image substitution, signed digest metadata, and workflow artifact publication.
- [ ] Render manifests, run validator tests and container builds, then run the full gate.
- [ ] Publish, integrate `main`, pass CI/review, and merge.

### Task 5: Operational telemetry and trace propagation

**Files:** Create API telemetry middleware and metric registry modules; modify scheduler, idempotency, reconciliation, worker/agent request context, jobs migration, and metric tests.

**Interfaces:** Expose bounded Prometheus counters/histograms and persist W3C `traceparent` with queued work.

- [ ] Add failing tests for route-template labels, error codes, latency families, lease/provider/idempotency outcomes, forbidden high-cardinality labels, and trace propagation.
- [ ] Implement registry/middleware and worker spans with no request-result coupling.
- [ ] Run focused cardinality/trace tests and the full gate.
- [ ] Publish, integrate `main`, pass CI/review, and merge.

### Task 6: Complete OpenAPI coverage

**Files:** Modify API annotations/document generation and public API tests; modify release workflow.

**Interfaces:** Produce one documented operation for every public `/v1` method/path and publish `sandboxwich-openapi.json`.

- [ ] Add a failing router-versus-OpenAPI parity test listing current omissions.
- [ ] Annotate missing handlers and schemas until parity passes.
- [ ] Add deterministic schema generation and release artifact verification.
- [ ] Run parity tests and the full gate; publish, integrate `main`, pass CI/review, and merge.

### Task 7: Split large Rust modules

**Files:** Extract worker provider contracts/manifests/execution/tests, core client/resource modules, and focused command modules while preserving re-exports.

**Interfaces:** Keep existing crate public paths and CLI behavior stable.

- [ ] Add or identify characterization tests for public exports and CLI help snapshots before each extraction.
- [ ] Move one responsibility at a time, run focused tests after each move, and commit each extraction atomically.
- [ ] Run the full gate and compare generated OpenAPI before/after.
- [ ] Publish, integrate `main`, pass CI/review, and merge.

### Task 8: Maturity gates and first release

**Files:** Replace stale roadmap state; update capabilities, changelog, README, and release workflow.

**Interfaces:** Define objective Experimental-to-Supported gates and publish schema, CLI archives, checksums, attestations, and image digest inventory.

- [ ] Add documentation integrity checks for capability names, roadmap status, and release artifact inventory.
- [ ] Update docs and workflow, then run prose and workflow validation plus the full gate.
- [ ] Publish, integrate `main`, pass CI/review, and merge.
- [ ] Tag the first eligible version, monitor release jobs, download artifacts, verify checksums/attestations/schema/signatures, and record the release URL.

### Final integration

- [ ] Confirm all eight PRs are merged and all referenced issues closed.
- [ ] Verify current `main` CI, containers, and Kubernetes conformance succeed together.
- [ ] Read back the active ruleset, latest release, artifacts, and signed image digests.
- [ ] Report every merged PR ID and the release URL.
