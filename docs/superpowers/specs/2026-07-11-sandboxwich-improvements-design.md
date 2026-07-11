# Sandboxwich Improvement Wave Design

## Scope

This wave ships eight approved improvements: sandbox-bound guest authorization, FQDN egress, protected `main`, digest-pinned deployment artifacts, operational telemetry, complete OpenAPI coverage, smaller Rust modules, and release-oriented maturity criteria.

## Delivery shape

Each independently reviewable change lands through its own pull request. Every branch starts from current `main`, merges current `main` again before landing, runs the repository's full local gate, and uses a merge commit. GitHub configuration is applied only after the workflow that supplies its required checks is present on `main`.

## Authorization

The API mints opaque random guest tokens and stores only their SHA-256 hashes. Each token row binds one tenant, worker, sandbox, capability set, expiry, and revocation timestamp. Guest routes authenticate this principal separately from tenant and worker credentials. Lease claim, renew, completion, failure, command-output append, and guest-health handlers verify the sandbox and job kind against the principal. Provisioning creates a per-sandbox Secret without placing raw token material in provider metadata, logs, plans, or API responses. Teardown revokes the credential and deletes the Secret.

## FQDN egress

`NetworkAllowRule::Host` remains provider-neutral. Kubernetes apply mode supports it only when an explicit FQDN backend is configured. The first backend renders Cilium `CiliumNetworkPolicy` `toFQDNs` rules because it enforces DNS-derived destinations without routing TLS through a shared proxy. Standard Kubernetes NetworkPolicy continues rejecting hosts. Provider capability reports expose FQDN support, and conformance checks allowed DNS, denied DNS, redirects, unavailable DNS, IPv4, and IPv6 behavior. The default remains fail-closed.

## Repository and artifacts

A GitHub repository ruleset requires pull requests, prevents force pushes and deletion, and requires the stable CI, Clippy, audit, MSRV, container, and Kubernetes conformance checks. Deployment manifests become Kustomize bases with image placeholders. CI publishes signed multi-architecture images and a reviewed overlay records immutable digests; migration and API containers share one API digest.

## Telemetry

The API records request totals and duration by method, route template, status, and stable error code. Scheduler and worker metrics cover queue delay, lease outcomes, retries, provider operation duration, reconciliation, rollback failure, heartbeat age, capacity, and idempotency results. Labels exclude tenant, sandbox, job, command, lease, and request identifiers. W3C trace context is persisted with jobs and emitted by workers and agents.

## API contract

Every public `/v1` route is represented in the generated OpenAPI document. A test normalizes router method/path pairs and fails when the document omits one. The release workflow publishes the schema beside binaries.

## Module boundaries

Large files are split without changing public behavior. Worker providers separate contracts, Kubernetes manifests, Kubernetes execution, and tests. Core separates clients and resource contracts behind existing re-exports. Agent, worker, CLI, and benchmark command dispatch move to focused modules when the extraction reduces the touched hot path. Each extraction is proven by the existing suite plus module-specific tests.

## Maturity and releases

The roadmap records shipped milestones and defines promotion gates for authentication, isolation, lifecycle recovery, conformance, telemetry, documentation, and supported providers. The first release is created only after those gates and all required checks pass. Release artifacts include CLI archives, checksums, attestations, OpenAPI, and image digests.

## Failure handling

All new security paths fail closed. Expired, revoked, cross-sandbox, wrong-kind, and wrong-worker guest credentials return stable error codes. Unsupported FQDN providers reject creation before a job is queued. Metrics failures do not change request results. Artifact promotion refuses missing or mismatched digests.

## Verification

Behavioral changes use red-green tests. Each PR runs `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`; database contract changes also run the PostgreSQL suite. Networking changes run kind conformance. GitHub changes are verified through the REST API and a protected-branch dry run. Releases are verified by downloading artifacts and checking checksums, attestations, schema, and image signatures.
