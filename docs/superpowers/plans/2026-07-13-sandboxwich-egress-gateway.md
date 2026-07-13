# Sandboxwich Egress Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every host-based Sandbox egress rule through a per-Sandbox proxy that validates DNS answers and blocks private, link-local, metadata, cluster, and control-plane addresses.

**Architecture:** The existing `sandboxwich-worker` image gains an `egress-gateway` command. A host-bearing Sandbox gets a dedicated gateway Pod and Service, a Sandbox NetworkPolicy that permits DNS and the gateway port, and a gateway NetworkPolicy that excludes protected CIDRs. The gateway resolves each requested host once per connection, rejects the connection if one returned address is protected, and connects to one validated address without a second DNS lookup.

**Tech Stack:** Rust 1.95, Tokio TCP and DNS APIs, `ipnet`, Kubernetes manifests rendered by `sandboxwich-worker`, GitHub Actions native amd64/arm64 images, GKE, Argo CD.

## Global Constraints

- No workflow may install QEMU or binfmt.
- Exact host rules and one leading `*.` wildcard are accepted; other wildcard forms are rejected.
- Gateway DNS results that contain a protected address deny the connection.
- Sandbox Pods cannot connect directly to public IP addresses when their policy contains host rules.
- Gateway, DNS, or policy parsing failure denies egress.
- The gateway listener accepts HTTP proxy requests and HTTP `CONNECT` only on policy-approved ports.
- Each tunneled connection ends after 300 seconds.
- Gateway Pods use the exact `sandboxwich-worker` digest configured on the worker Deployment.
- Audit events use a SHA-256 policy identity. Raw tenant and Sandbox IDs do not appear as metric labels.

---

### Task 1: Gateway policy evaluator and TCP proxy

**Files:**
- Create: `crates/sandboxwich-worker/src/egress_gateway.rs`
- Create: `crates/sandboxwich-worker/src/egress_gateway/tests.rs`
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Modify: `crates/sandboxwich-worker/Cargo.toml`

**Interfaces:**
- Consumes: `NetworkAllowRule`, `NetworkAllowRuleKind`, and `ipnet::IpNet`.
- Produces: `EgressGatewayPolicy`, `ResolvedTarget`, `evaluate_target`, and `run_egress_gateway`.

- [ ] **Step 1: Write failing policy tests**

```rust
#[test]
fn policy_accepts_exact_and_controlled_wildcard_hosts() {
    let policy = policy(&["api.example.com", "*.packages.example.com"]);
    assert!(policy.allows_host("api.example.com"));
    assert!(policy.allows_host("v1.packages.example.com"));
    assert!(!policy.allows_host("packages.example.com"));
    assert!(!policy.allows_host("example.com"));
}

#[test]
fn one_protected_dns_answer_denies_the_target() {
    let policy = policy(&["api.example.com"]);
    let result = evaluate_target(
        &policy,
        "api.example.com",
        443,
        ["203.0.113.10".parse().unwrap(), "169.254.169.254".parse().unwrap()],
    );
    assert_eq!(result.unwrap_err().reason_code(), "protected_dns_answer");
}
```

- [ ] **Step 2: Run the tests and confirm the missing-module failure**

Run: `cargo test -p sandboxwich-worker egress_gateway --no-run`

Expected: compilation fails because `egress_gateway` and its policy types do not exist.

- [ ] **Step 3: Implement the policy types and protected CIDR set**

```rust
pub(crate) const DEFAULT_GATEWAY_DENY_CIDRS: &[&str] = &[
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct EgressGatewayPolicy {
    pub policy_id: String,
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub denied_cidrs: Vec<IpNet>,
    pub connection_lifetime_seconds: u64,
}
```

`allows_host` must lowercase the request, remove one trailing dot, compare exact rules, and require at least one label before a wildcard suffix. `evaluate_target` must validate the host and port, reject an empty DNS answer, reject the target when any answer belongs to `denied_cidrs`, and return the first validated `SocketAddr`.

- [ ] **Step 4: Write failing parser and connection-fence tests**

```rust
#[tokio::test]
async fn connect_uses_the_validated_socket_without_reresolving() {
    let resolver = FakeResolver::new(["203.0.113.10".parse().unwrap()]);
    let connector = RecordingConnector::default();
    handle_connect(&policy(&["api.example.com"]), &resolver, &connector,
        b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n").await.unwrap();
    assert_eq!(resolver.calls(), 1);
    assert_eq!(connector.targets(), ["203.0.113.10:443".parse().unwrap()]);
}
```

- [ ] **Step 5: Implement bounded HTTP proxy handling**

`run_egress_gateway` must bind the configured address, cap request headers at 16 KiB, impose a 10-second header timeout, support `CONNECT host:port`, support absolute-form `http://host[:port]/path` requests, emit `403` for policy denies, emit `502` for DNS/connect failures, and wrap `tokio::io::copy_bidirectional` in a 300-second timeout. Each decision must emit one JSON line containing `policy_id`, `host_hash`, `port`, `decision`, and `reason_code`.

- [ ] **Step 6: Add the CLI command**

```rust
#[derive(Debug, Args)]
struct EgressGatewayArgs {
    #[arg(long, env = "SANDBOXWICH_EGRESS_GATEWAY_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    #[arg(long, env = "SANDBOXWICH_EGRESS_GATEWAY_POLICY")]
    policy: String,
}
```

Add `Command::EgressGateway(EgressGatewayArgs)` and call `run_egress_gateway` after parsing the JSON policy.

- [ ] **Step 7: Run and commit the gateway tests**

Run: `cargo fmt --check && cargo clippy -p sandboxwich-worker --all-targets -- -D warnings && cargo test -p sandboxwich-worker egress_gateway`

Expected: every command exits zero.

Commit: `git commit -am 'feat(worker): add bounded egress gateway'`

---

### Task 2: Kubernetes provider gateway resources

**Files:**
- Modify: `crates/sandboxwich-worker/src/provider.rs`
- Modify: `crates/sandboxwich-worker/src/provider/tests.rs`
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Modify: `deploy/kubernetes/worker.yaml`
- Modify: `docs/kubernetes.md`

**Interfaces:**
- Consumes: `EgressGatewayPolicy` from Task 1 and `SandboxProvisionSpec.network_egress`.
- Produces: `with_egress_gateway_image`, gateway Pod/Service manifests, Sandbox and gateway NetworkPolicies, and tracked runtime resources.

- [ ] **Step 1: Replace native GKE policy tests with failing gateway manifest tests**

```rust
#[test]
fn host_rules_render_a_separate_gateway_and_no_direct_public_egress() {
    let rendered = provider().with_egress_gateway_image(Some(worker_image())).provision(
        SandboxId::new(), &host_spec("api.example.com"), &CancelSignal::never_cancelled()
    ).unwrap();
    assert_resource(&rendered, "Pod", "sandboxwich-egress-gateway-");
    assert_resource(&rendered, "Service", "sandboxwich-egress-gateway-");
    assert_sandbox_egress_only_targets_gateway_and_dns(&rendered);
    assert_gateway_egress_excludes(DEFAULT_GATEWAY_DENY_CIDRS, &rendered);
}
```

Delete assertions for `networking.gke.io/v1alpha1`, `FQDNNetworkPolicy`, and `SANDBOXWICH_GKE_FQDN_EGRESS`.

- [ ] **Step 2: Run the provider tests and confirm they fail**

Run: `cargo test -p sandboxwich-worker host_rules_render_a_separate_gateway_and_no_direct_public_egress -- --nocapture`

Expected: the gateway Pod and Service are absent.

- [ ] **Step 3: Add the explicit gateway image contract**

Add `egress_gateway_image: Option<String>` to `KubernetesDryRunProvider`, a `with_egress_gateway_image` builder, and `--egress-gateway-image` / `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` to `ProviderArgs`. Apply mode must reject host rules with `egress_gateway_image_required` when the image is absent or is not digest-pinned.

- [ ] **Step 4: Render gateway resources**

For a Sandbox with host rules, render:

```yaml
kind: Pod
metadata:
  name: sandboxwich-egress-gateway-<sandbox-id>
spec:
  automountServiceAccountToken: false
  containers:
    - name: gateway
      image: <digest-pinned worker image>
      args: ["egress-gateway"]
      env:
        - name: SANDBOXWICH_EGRESS_GATEWAY_POLICY
          value: '<serialized policy>'
```

The Sandbox Pod receives `HTTP_PROXY` and `HTTPS_PROXY` pointing at the gateway Service. Its NetworkPolicy permits DNS and TCP 8080 to the gateway Pod selector. The gateway NetworkPolicy permits DNS and policy ports to public CIDRs with every protected CIDR in `except`. Render the gateway before the Sandbox Pod and report a durable `NetworkPolicyReady` stage only after both policies apply.

- [ ] **Step 5: Track, adopt, roll back, reconcile, and delete gateway resources**

Add gateway Pod, Service, and NetworkPolicy entries to `ProviderSandboxHandle.resources`. Adoption must compare the image digest, serialized policy hash, security context, and selectors. Rollback and stop continue using the Sandbox label selector, so they delete both Pods, the Service, the Secret, PVC, and both NetworkPolicies in one fenced operation.

- [ ] **Step 6: Update checked-in worker deployment**

Set `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` to the same digest-pinned `sandboxwich-worker` image used by the Deployment. Remove `networking.gke.io` RBAC and every GKE FQDN environment flag because the gateway uses core Pods, Services, Secrets, and NetworkPolicies only.

- [ ] **Step 7: Run and commit provider coverage**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features`

Expected: every command exits zero; PostgreSQL-only tests may report their documented skip when no PostgreSQL URL is configured.

Commit: `git commit -am 'feat(worker): provision per-sandbox egress gateways'`

---

### Task 3: Public policy validation and conformance

**Files:**
- Modify: `crates/sandboxwich-api/src/handlers/sandboxes.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/sandboxes.rs`
- Modify: `deploy/kubernetes/kind-conformance.sh`
- Modify: `.github/workflows/kubernetes-conformance.yml`

**Interfaces:**
- Consumes: the existing `NetworkEgress::Allowlist` request.
- Produces: controlled wildcard validation and live deny/allow assertions.

- [ ] **Step 1: Write failing wildcard validation tests**

Accept `*.packages.example.com`. Reject `*`, `api.*.example.com`, `**.example.com`, `.example.com`, and wildcard CIDR rules. Preserve lowercase-only DNS names and the 253-byte limit.

- [ ] **Step 2: Implement controlled wildcard validation**

Split one leading `*.` before calling `looks_like_dns_name` on the base. Require the base to contain at least one dot. Keep `provision_capability` and `fork_capability` mapped to `WorkerCapability::FqdnEgress` for every host rule.

- [ ] **Step 3: Add conformance assertions**

The live suite must create a host-bearing Sandbox and assert:

1. The gateway Pod reaches Ready.
2. A request to the allowed fixture host through `HTTPS_PROXY` succeeds.
3. An unlisted host returns a gateway deny.
4. `169.254.169.254`, a direct public IP, and a fixture hostname resolving to a private IP fail.
5. Deleting the gateway Pod does not permit direct egress.
6. Stopping the Sandbox removes the gateway Pod, Service, and policies.

- [ ] **Step 4: Run and commit contract and conformance tests**

Run: `cargo test -p sandboxwich-api --test http_contract && cargo test -p sandboxwich-worker && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features`

Expected: the HTTP contract, worker, workspace lint, and workspace test gates pass.

Commit: `git commit -am 'test(egress): cover gateway policy boundaries'`

---

### Task 4: Deploy contract and production proof

**Files:**
- Modify in `evalops/deploy`: `k8s/production/remote-runner/sandboxwich-worker.yaml`
- Modify in `evalops/deploy`: `k8s/sandboxwich-runtime/production/worker-rbac.yaml`
- Modify in `evalops/deploy`: `scripts/sandboxwich-production-smoke.sh`
- Modify in `evalops/deploy`: `.github/workflows/sandboxwich-production-proof.yml`
- Modify in `evalops/deploy`: `tests/preflight/test_sandboxwich_delivery.py`
- Modify in `evalops/deploy`: `docs/runbooks/sandboxwich-slos.md`

**Interfaces:**
- Consumes: the promoted `sandboxwich-worker` digest and its `egress-gateway` command.
- Produces: production gateway configuration and `sandboxwich.egress-gateway-proof.v1` evidence.

- [ ] **Step 1: Write failing Deploy preflight assertions**

Assert that production sets `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` to the worker digest, grants no `networking.gke.io` permission, and that production proof checks allowed host, unlisted host, direct IP, metadata IP, private DNS answer, and gateway outage.

- [ ] **Step 2: Configure production without a cluster migration**

Set the gateway image environment value to the promoted worker digest. Remove the GKE FQDN worker flag and custom-resource RBAC. Keep GKE capability evidence in diagnose mode so the artifact records why native FQDN policy is not the enforcement boundary.

- [ ] **Step 3: Extend the production smoke**

Create one bounded disposable host-bearing Sandbox. Execute the six assertions from Task 3 through the Sandbox command API. Hash the Sandbox ID in evidence and write:

```json
{
  "schema_version": "sandboxwich.egress-gateway-proof.v1",
  "allowed_host": true,
  "unlisted_host_denied": true,
  "direct_ip_denied": true,
  "metadata_denied": true,
  "private_dns_answer_denied": true,
  "gateway_outage_fail_closed": true
}
```

Cleanup must use the product stop path and wait for terminal archived state.

- [ ] **Step 4: Run Deploy gates and commit**

Run: `bash -n scripts/sandboxwich-production-smoke.sh && shellcheck scripts/sandboxwich-production-smoke.sh && actionlint .github/workflows/sandboxwich-production-proof.yml && /usr/bin/python3 -m pytest tests/preflight/test_sandboxwich_delivery.py -q && kubectl kustomize k8s/production >/dev/null`

Expected: every command exits zero.

Commit: `git commit -am 'deploy(sandboxwich): enforce host egress through gateway'`

---

### Task 5: Merge, promote, and prove production

**Files:**
- No source edits unless CI, review, GitOps convergence, or production proof identifies a specific defect.

**Interfaces:**
- Consumes: merged Sandboxwich and Deploy heads.
- Produces: merge commits, promoted signed indexes, exact deployed revision evidence, and terminal proof artifacts.

- [ ] **Step 1: Audit every review thread**

Query `reviewThreads(first:100)` for source and Deploy PRs. Reply to and resolve each actionable thread, including outdated threads. Re-run review on each final head.

- [ ] **Step 2: Merge source and verify native images**

Wait for Rust, MSRV, audit, Cilium, kind, amd64, arm64, provenance, SBOM, signature, and index checks. Verify the merge commit is reachable from `main`. Wait for the successful `containers.yml` push run for that merge commit.

- [ ] **Step 3: Promote and merge production indexes**

Dispatch `sync-sandboxwich-production-images.yml` with the exact source run ID. Verify source SHA, provenance, SBOM, source signatures, mirrored signatures, and the generated Deploy PR. Shepherd that PR through the full Deploy gate and merge it.

- [ ] **Step 4: Run one final exact-revision proof**

Dispatch `sandboxwich-production-proof.yml` on the current Deploy `main` with the exact current SHA, `recovery_drill=true`, `alert_route_drill=true`, `gke_fqdn=diagnose`, and a reason of at least 12 non-whitespace characters. Cancel and restart only if Deploy `main` advances before Argo reaches the expected SHA.

- [ ] **Step 5: Inspect artifacts and close the goal**

Require passing revision, lifecycle, warm-capacity, recovery, exact alert delivery, GKE diagnostic, and egress-gateway evidence. Record the source SHA, Deploy SHA, image digests, artifact digest, rollback reference, and every final merge commit before marking the goal complete.
