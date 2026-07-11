# Roadmap and support gates

## Shipped in 0.1

- Typed `/v1` HTTP control plane with SQLite and PostgreSQL contract tests.
- Durable worker registration, capacity, leases, renewal, retry, and typed completion.
- Guest command streaming, file operations, health, SSH metadata, and sandbox-bound tokens.
- Snapshot, fork, retention, cleanup, desktop-session, and runtime-resource records.
- Kubernetes dry-run and guarded apply providers with RuntimeClass, ingress, CIDR egress, and optional Cilium FQDN policy.
- Signed API, worker, and Ubuntu runtime images plus attested CLI archives.

These capabilities remain Experimental until every gate below passes for a named provider and release.

## Promotion gates

### Authorization

- Tenant, operator, worker, and guest principals have separate credentials and route permissions.
- Guest credentials are bound to one sandbox, expire, rotate by revocation, and never appear in logs, provider metadata, process arguments, or stored response bodies.
- SQLite and PostgreSQL tests cover cross-tenant, cross-worker, cross-sandbox, expiry, revocation, and wrong-job-kind requests.

### Isolation

- The supported provider uses gVisor, Kata, a microVM, or an equivalent documented boundary.
- Sandbox pods cannot reach Kubernetes, cloud metadata, control-plane namespaces, or another sandbox unless an explicit policy permits the destination.
- FQDN and CIDR allowlists have live allow, deny, DNS failure, redirect, IPv4, and IPv6 tests.

### Lifecycle recovery

- Provision, command, stop, snapshot, fork, cancellation, lease loss, worker restart, API restart, and out-of-band resource deletion have deterministic terminal states.
- Cleanup and reconciliation are idempotent and retain an operator-readable record of failures.

### Conformance

- The provider passes the disposable-cluster suite from a clean database and empty cluster.
- SQLite and PostgreSQL contract suites pass on the release commit.
- Required Rust, Clippy, dependency audit, MSRV, container, and Kubernetes checks pass together on current `main`.

### Telemetry

- Metrics expose bounded-label sandbox, worker, job, lease, queue age, heartbeat age, retry, idempotency, cleanup, runtime-resource, and guest-token state.
- Alerts cover queued-work age, stale workers, repeated lease expiry, cleanup failure, and capacity exhaustion.
- Tenant credentials cannot read another tenant's metrics; the operator credential can read the global view.

### Documentation

- Every public `/v1` method and path appears in the released OpenAPI document.
- The capability matrix names the provider, backend, limitations, and support state.
- The release contains CLI archives, checksums, provenance attestations, OpenAPI, and image digests.

## Next work

1. Add live Cilium FQDN conformance on a Cilium-backed disposable cluster.
2. Add a microVM provider and compare its lifecycle and recovery behavior with RuntimeClass-backed Kubernetes.
3. Add a brokered desktop transport; current desktop records do not create an ingress tunnel.
4. Add production secret storage before accepting long-lived user or model credentials.

## Non-goals for 0.1

- Billing.
- Long-lived production secret storage.
- Unsupported isolation claims for the dry-run provider.
