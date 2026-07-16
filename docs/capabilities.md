# Capability maturity

This matrix is the product contract. A capability is not considered supported
until its real provider path is exercised by an end-to-end conformance test.

| Capability | Status | Notes |
|---|---|---|
| Typed HTTP control plane | Experimental | SQLite for local development; Postgres for shared deployments. |
| Typed execution classes | Experimental | Callers request `development_container`, `sandboxed_container`, or `virtual_machine`; workers advertise operator-configured isolation support. VM execution remains experimental until SW-3 live conformance certification passes. |
| Kubernetes pod provisioning | Experimental | Apply mode mutates a configured sandbox namespace. Require gVisor or Kata for hostile multi-tenant workloads. |
| FQDN egress allowlists | Experimental | Workers with a digest-pinned `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` provision a per-Sandbox proxy and fail-closed NetworkPolicies. Cilium-managed namespaces may use `SANDBOXWICH_CILIUM_FQDN_EGRESS=true`. Native additive GKE FQDN policy is not an enforcement boundary. |
| Command execution | Experimental | Kubernetes apply mode uses `kubectl exec`; dry-run mode is simulation only. Command requests may carry up to 1 MiB of base64-encoded, non-secret stdin bytes; providers pipe the decoded bytes to the guest and close the stream. |
| APEX task instructions | Experimental | Apply-mode workers use one fixed executable and return at most 1 MiB through an instance-affine, worker-authenticated callback. Plaintext is live-only; durable rows contain lineage, digest, and byte count. Replays report output unavailable. |
| Snapshots and forks | Experimental | Requires a working CSI `VolumeSnapshotClass`; not all clusters support it. |
| SSH and browser desktop metadata | Experimental | Access records do not provide an ingress tunnel by themselves. |
| Prompt/model execution | Unsupported | The current worker has no model executor. Dry-run acknowledgements are not model output. |
| True resume after teardown | Unsupported | Stop destroys resources; create or fork a replacement instead. |
| Guest-agent lease claim scoping | Experimental | Workers mint opaque `sbw_gtok_` credentials bound to one tenant, worker, sandbox, and expiry. Guest claims are limited to `run_command` and `run_resident_process`; the API rejects omitted filters, cross-sandbox claims, other job kinds, worker administration, expiry, and revocation. Raw tokens are returned once and stored only as SHA-256 hashes. |
| Resident guest processes | Experimental | A tenant may create one `orb-executor` resident process per sandbox. Bootstrap bytes are held in one API replica until a sandbox-scoped guest consumes them once; durable rows contain only digest and byte count. Production routing must keep the create and bootstrap-read requests on the same API replica until a shared ephemeral handoff is added. |
| Production secret storage and billing | Unsupported | Explicit non-goals for the current milestone. |

Provider capability reports must distinguish `dry_run` from `apply`; clients
must not treat a simulated result as evidence that runtime work occurred.
Only `provider_mode=apply` is real-provider execution evidence;
`provider_mode=dry_run` is never proof that a guest process ran.

## Execution class ownership

Callers select the workload requirement through the typed `execution_class`
field. Omitting it preserves the compatibility default of
`development_container`. The selected class is durable, is inherited by forks,
and constrains worker claim routing. It does not name a Kubernetes
`RuntimeClass`, choose a node, or prove that a cluster isolation backend works.
The closed apex_trusted_supervisor_v1 runtime profile is an additional,
conjunctive trust requirement: the API accepts it only with
execution_class=sandboxed_container, and a worker may advertise it only with
--isolation-profile gvisor, a nonempty RuntimeClass, and the exact
digest-pinned APEX image. Snapshot/fork and claim-time authoritative refresh
preserve both dimensions; neither profile can downgrade the other.


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
