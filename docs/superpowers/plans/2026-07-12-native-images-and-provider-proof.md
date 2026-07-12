# Native Images and Provider Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish amd64 and arm64 images on native GitHub runners, assemble signed OCI indexes, and add live Cilium plus lifecycle-recovery proof.

**Architecture:** Architecture-specific jobs build and push immutable temporary tags on matching hosted runners. Index jobs join those digests under the release tags and sign the resulting index. Kubernetes conformance keeps its existing required context while separate scripts exercise Cilium DNS policy and destructive recovery cases.

**Tech Stack:** GitHub Actions, Docker Buildx, Cosign, Rust, kind, Cilium, Kubernetes, Bash, Python unittest.

## Global Constraints

- No QEMU or binfmt emulation.
- Preserve required check names in `.github/rulesets/main.json`.
- Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before pushing.
- Merge commits only; never force-push.

---

### Task 1: Native image build contract

**Files:**
- Modify: `.github/workflows/containers.yml`
- Modify: `scripts/test-repository-rules.py`

**Interfaces:**
- Produces: per-architecture digest artifacts and final `service image (...)` / `runtime image (ubuntu-dev)` check contexts.

- [ ] Write assertions that require `ubuntu-24.04` for amd64, `ubuntu-24.04-arm` for arm64, forbid `qemu`/`binfmt`, and require OCI index assembly.
- [ ] Run `python3 scripts/test-repository-rules.py` and observe the native-build assertions fail.
- [ ] Split service and runtime builds by architecture, upload digest artifacts, and assemble signed indexes only on `main`.
- [ ] Run the repository rule tests and inspect `actionlint` output when available.
- [ ] Commit the native build change.

### Task 2: Cilium FQDN conformance

**Files:**
- Create: `deploy/kubernetes/kind-cilium.yaml`
- Create: `deploy/kubernetes/cilium-fqdn-conformance.sh`
- Modify: `.github/workflows/kubernetes-conformance.yml`
- Create: `scripts/test-cilium-conformance.py`

**Interfaces:**
- Produces: a `cilium-fqdn` CI job proving allowed DNS, denied DNS, redirect handling, metadata denial, control-plane denial, IPv4, and IPv6 policy rendering/enforcement.

- [ ] Write a static contract test for a no-default-CNI kind cluster and all required assertions.
- [ ] Run it and observe missing files/job failures.
- [ ] Add the cluster config, pinned Cilium install, policy generation, and live probes.
- [ ] Run the static contract test and shell syntax checks.
- [ ] Commit the Cilium proof.

### Task 3: Destructive recovery conformance

**Files:**
- Modify: `deploy/kubernetes/kind-conformance.sh`
- Create: `scripts/test-recovery-conformance.py`

**Interfaces:**
- Produces: live proof for API restart, worker restart, lease loss, out-of-band pod deletion, reconciliation, and idempotent cleanup.

- [ ] Write contract assertions for every destructive case and terminal-state check.
- [ ] Run the test and observe missing recovery cases.
- [ ] Extend the live conformance script with bounded recovery drills and leak checks.
- [ ] Run static tests, `bash -n`, and the full Rust gate.
- [ ] Commit the recovery proof.

### Task 4: Ship and integrate

- [ ] Merge current `main`, rerun every local gate, push, and open a semantic PR.
- [ ] Wait for required checks plus Cilium conformance, address review threads, and merge.
- [ ] Verify the `main` container run emits three signed multi-architecture indexes.
