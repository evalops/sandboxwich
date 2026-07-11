# Capability maturity

This matrix is the product contract. A capability is not considered supported
until its real provider path is exercised by an end-to-end conformance test.

| Capability | Status | Notes |
|---|---|---|
| Typed HTTP control plane | Experimental | SQLite for local development; Postgres for shared deployments. |
| Kubernetes pod provisioning | Experimental | Apply mode mutates a configured sandbox namespace. Require gVisor or Kata for hostile multi-tenant workloads. |
| FQDN egress allowlists | Experimental | Workers configured with `SANDBOXWICH_CILIUM_FQDN_EGRESS=true` render Cilium `toFQDNs` policy and advertise `fqdn_egress`. Standard Kubernetes NetworkPolicy workers reject host rules. |
| Command execution | Experimental | Kubernetes apply mode uses `kubectl exec`; dry-run mode is simulation only. |
| Snapshots and forks | Experimental | Requires a working CSI `VolumeSnapshotClass`; not all clusters support it. |
| SSH and browser desktop metadata | Experimental | Access records do not provide an ingress tunnel by themselves. |
| Prompt/model execution | Unsupported | The current worker has no model executor. Dry-run acknowledgements are not model output. |
| True resume after teardown | Unsupported | Stop destroys resources; create or fork a replacement instead. |
| Guest-agent lease claim scoping | Advisory only | `sandboxwich-agent`'s daemon passes `sandbox_id`/`kinds` filters on `POST /workers/{id}/leases/claim` so it only claims `run_command` jobs for its own sandbox, and the API enforces those filters server-side. This narrows the default blast radius of a well-behaved agent, but it is **not tenant/sandbox isolation**: the guest and the worker it runs under share one worker-scoped token, so a compromised guest can omit the filters and claim (and forge completions for) any job that token's capabilities allow. Treat every guest-agent deployment as trusting its worker's full capability set until per-sandbox claim tokens exist. |
| Production secret storage and billing | Unsupported | Explicit non-goals for the current milestone. |

Provider capability reports must distinguish `dry_run` from `apply`; clients
must not treat a simulated result as evidence that runtime work occurred.
