# Capability maturity

This matrix is the product contract. A capability is not considered supported
until its real provider path is exercised by an end-to-end conformance test.

| Capability | Status | Notes |
|---|---|---|
| Typed HTTP control plane | Experimental | SQLite for local development; Postgres for shared deployments. |
| Typed execution classes | Experimental | Callers request `development_container`, `sandboxed_container`, or `virtual_machine`; workers advertise operator-configured isolation support. VM execution remains experimental until SW-3 live conformance certification passes. |
| Kubernetes pod provisioning | Experimental | Apply mode mutates a configured sandbox namespace. Require gVisor or Kata for hostile multi-tenant workloads. |
| FQDN egress allowlists | Experimental | Workers with a digest-pinned `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` provision a per-Sandbox proxy and fail-closed NetworkPolicies. Cilium-managed namespaces may use `SANDBOXWICH_CILIUM_FQDN_EGRESS=true`. Native additive GKE FQDN policy is not an enforcement boundary. |
| Command execution | Experimental | Kubernetes apply mode uses `kubectl exec`; dry-run mode is simulation only. |
| Snapshots and forks | Experimental | Requires a working CSI `VolumeSnapshotClass`; not all clusters support it. |
| SSH and browser desktop metadata | Experimental | Access records do not provide an ingress tunnel by themselves. |
| Prompt/model execution | Unsupported | The current worker has no model executor. Dry-run acknowledgements are not model output. |
| True resume after teardown | Unsupported | Stop destroys resources; create or fork a replacement instead. |
| Guest-agent lease claim scoping | Experimental | Workers mint opaque `sbw_gtok_` credentials bound to one tenant, worker, sandbox, expiry, and `run_command` lease surface. The API rejects omitted filters, cross-sandbox claims, non-command leases, worker administration, expiry, and revocation. Raw tokens are returned once and stored only as SHA-256 hashes. |
| Production secret storage and billing | Unsupported | Explicit non-goals for the current milestone. |

Provider capability reports must distinguish `dry_run` from `apply`; clients
must not treat a simulated result as evidence that runtime work occurred.

## Execution class ownership

Callers select the workload requirement through the typed `executionClass`
field. Omitting it preserves the compatibility default of
`development_container`. The selected class is durable, is inherited by forks,
and constrains worker claim routing. It does not name a Kubernetes
`RuntimeClass`, choose a node, or prove that a cluster isolation backend works.

Operators configure how workers satisfy that request:

| Worker isolation profile | Additional hostile-workload capability | Operator requirements |
|---|---|---|
| `development` | None | Development workloads; no hostile-workload isolation claim. |
| `gvisor` | `sandboxed_container` | A nonempty operator-owned RuntimeClass plus compatible nodes and runtime handler. |
| `kata` | `virtual_machine` | A nonempty operator-owned RuntimeClass plus compatible nodes and Kata runtime handler. |

Set the bounded profile with `--isolation-profile` or
`SANDBOXWICH_ISOLATION_PROFILE`. The raw `--runtime-class-name` value remains a
separate operator input used to render Pods; Sandboxwich does not infer a
profile from that name, discover or create RuntimeClasses, or inspect node
handlers. Hostile-workload capabilities cannot be added with a generic
`--capability` override.

The operator also owns node placement and runtime installation, enforceable CNI
policy, storage and CSI snapshot support, and live conformance evidence for the
chosen cluster. Registration and dry-run provider reports describe configured
capability, not readiness or certification. In particular,
`virtual_machine`/Kata execution is experimental and must not be treated as
certified until the SW-3 live conformance gate passes.
