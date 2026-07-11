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
| Guest-agent lease claim scoping | Experimental | Workers mint opaque `sbw_gtok_` credentials bound to one tenant, worker, sandbox, expiry, and `run_command` lease surface. The API rejects omitted filters, cross-sandbox claims, non-command leases, worker administration, expiry, and revocation. Raw tokens are returned once and stored only as SHA-256 hashes. |
| Production secret storage and billing | Unsupported | Explicit non-goals for the current milestone. |

Provider capability reports must distinguish `dry_run` from `apply`; clients
must not treat a simulated result as evidence that runtime work occurred.
