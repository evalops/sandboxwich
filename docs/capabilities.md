# Capability maturity

This matrix is the product contract. A capability is not considered supported
until its real provider path is exercised by an end-to-end conformance test.

| Capability | Status | Notes |
|---|---|---|
| Typed HTTP control plane | Experimental | SQLite for local development; Postgres for shared deployments. |
| Typed execution classes | Experimental | Callers request `development_container`, `sandboxed_container`, or `virtual_machine`; workers advertise operator-configured isolation support. VM execution remains experimental until SW-3 live conformance certification passes. |
| Kubernetes pod provisioning | Experimental | Apply mode mutates a configured sandbox namespace. Require gVisor or Kata for hostile multi-tenant workloads. |
| FQDN egress allowlists | Experimental | Workers with a digest-pinned `SANDBOXWICH_EGRESS_GATEWAY_IMAGE` provision a per-Sandbox proxy and fail-closed NetworkPolicies. Cilium-managed namespaces may use `SANDBOXWICH_CILIUM_FQDN_EGRESS=true`; the rendered `CiliumNetworkPolicy` is enforced live on a disposable Cilium cluster (`cilium-fqdn` job: allow, deny, DNS failure, redirect, IPv4, IPv6, port scope), but no production cluster runs Cilium, so the backend has no production evidence. Native additive GKE FQDN policy is not an enforcement boundary. |
| Command execution | Experimental | Kubernetes apply mode uses `kubectl exec`; dry-run mode is simulation only. Command requests may carry up to 1 MiB of base64-encoded, non-secret stdin bytes; providers pipe the decoded bytes to the guest and close the stream. |
| Foam compiler-cache restore | Experimental | Only unprivileged runtime profiles may request `compiler_cache_archive` materialization; root/APEX profiles are rejected while existing APEX destinations remain APEX-only. Standard runtime Pods use a root init container and root restore helper sharing only `/workspace`. The UID-10001 workload cannot select the helper through ordinary exec. Archives and their separately supplied bounded Foam identity stage beneath a root-only directory, then the provider invokes fixed restore before reporting success. Restore uses a no-clobber same-filesystem rename beneath a root-owned sticky cache parent and makes the tree workload-owned only after a bottom-up ownership handoff. Cold workloads may create `SCCACHE_DIR` themselves. This is an intra-Pod filesystem-integrity boundary, not isolation from a root workload or a compromised Kubernetes control plane. |
| APEX task instructions | Experimental | Apply-mode workers use one fixed executable and return at most 1 MiB through an instance-affine, worker-authenticated callback. Plaintext is live-only; durable rows contain lineage, digest, and byte count. Replays report output unavailable. |
| Snapshots and forks | Experimental | Requires a working CSI `VolumeSnapshotClass`; not all clusters support it. |
| SSH and browser desktop metadata | Experimental | SSH access records do not provide an ingress tunnel by themselves. Desktop access records now resolve a typed transport pointing at the sandbox's persisted desktop `Service` runtime resource and mint a short-lived, sandbox-bound credential; the external broker that terminates that credential and the public ingress in front of the `Service` are not yet part of this repo. |
| Prompt/model execution | Unsupported | The current worker has no model executor. Dry-run acknowledgements are not model output. |
| Snapshot-backed resume after teardown | Experimental | `POST /v1/sandboxes/{id}/resume` restores an `archived` sandbox in place from one of *its own* ready snapshots, keeping its id, creation time, and lifetime configuration. Requires `workspace_mode=persistent`, a same-sandbox ready snapshot whose placement and runtime profile still match, and therefore a working CSI `VolumeSnapshotClass`. Fails closed (`resume_snapshot_unavailable`, `resume_snapshot_foreign`, `resume_placement_mismatch`, `resume_lifetime_exhausted`) rather than restoring an empty workspace. Restores whatever the snapshot captured -- workspace volume state, not live process, memory, or in-flight command state. Exercised in apply mode only as far as the Kubernetes restore path is exercised elsewhere; the contract suite covers the API and dry-run provider paths. |
| Guest-agent lease claim scoping | Experimental | Workers mint opaque `sbw_gtok_` credentials bound to one tenant, worker, sandbox, and expiry. Guest claims are limited to `run_command` and `run_resident_process`; the API rejects omitted filters, cross-sandbox claims, other job kinds, worker administration, expiry, and revocation. Raw tokens are returned once and stored only as SHA-256 hashes. |
| Resident guest processes | Experimental | A tenant may create one `orb-executor` resident process per sandbox. A typed, exactly versioned agent-capability report gates dispatch. Bootstrap bytes remain in one API process and may be retried only by the same generation/lease/digest fence until the agent acknowledges that exact process as `Starting`; durable rows contain only digest and byte count. API restart, replica failover, and cross-replica replay remain unsupported until a shared ephemeral handoff is added. |
| Provider-isolated sidecar (`orb-sidecar`, v2) | Experimental | An apply-mode Kubernetes worker advertises `provider_isolated_resident_process_version=2` only with a digest-pinned `SANDBOXWICH_ISOLATED_RESIDENT_PROCESS_IMAGE` and a nonempty RuntimeClass. V2 keeps the dedicated Pod, immutable transient Secret, separate namespaces, no service-account token, restrictive security context, fenced cleanup, and deny-all ingress from v1. It additionally places a one-time, hash-only Sandboxwich placement proof in a second sidecar-only Secret file, records the authoritative Pod UID from Kubernetes observation, supports tenant-authenticated redemption plus record-bound live validation for Orb, and allows only explicitly configured narrow private issuer CIDRs over TCP/443. V1 rows remain readable during rollout, but only v2 receives an attestation. The sidecar does **not** share guest localhost; integrations use explicit HTTPS. Executor bootstrap remains fail-closed unless the sidecar is `Running` under a live lease. |
| Provider-isolated Maestro runner | Experimental | An apply-mode Kubernetes worker may host `maestro-hosted-runner` in a separate digest-pinned gVisor Pod. The Pod disables automatic service-account mounting and receives only a 600-second projected, pod-bound token with the exact Identity certificate-exchange audience. No token, private key, certificate, or bootstrap secret enters the guest Pod, guest volume, or snapshot. Identity must authenticate to the internal validation route and match the tenant, workspace, sandbox, observed Pod UID/name, placement and resident generations, runner session, image digest, live lease/attempt/expiry, and worker before issuing a short-lived server certificate. The generated Service admits runner-host traffic only; egress is deny-by-default except DNS and explicitly configured narrow HTTPS issuer CIDRs. |
| Active-lifetime reaping (`max_lifetime_seconds`) | Experimental | Background sweep stops a live sandbox past a hard cap measured from `created_at`, through the same path a user-initiated stop uses. Deterministic and fully tested end-to-end. Off by default (`None`); an operator must configure `SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS` or a caller must pass `max_lifetime_seconds` for anything to be reaped. |
| Active-lifetime reaping (`idle_ttl_seconds`) | Experimental | Same reap path as `max_lifetime_seconds`, but the deadline resets on the most recent of: the sandbox's last lifecycle-state transition, its most recently *queued* guest command, and `last_activity_at` -- a server-maintained timestamp bumped by SSH access, desktop access, and resident-process observation requests (throttled to at most once per 60s per sandbox; see `activity.rs`). Covers every guest-interaction surface this API currently exposes. |
| Secret references for long-lived credentials | Experimental | `/v1/secret-refs` stores tenant-scoped (`tenant_id` = platform organization, plus `workspace_id`) *locators* for long-lived user and model credentials held in an external store fronted by an operator-provisioned `SecretProviderClass` (`csi_secret_provider_class`). The typed contract has no field that can carry credential material in either direction, so no request, response, log line, or database column can hold a secret value. Reference names are validated before they become guest paths and revocation is a durable state transition. Revocation is bind-time only: `DELETE /v1/secret-refs/{id}` stops the reference from being bound to any *new* sandbox, but a sandbox already bound to it keeps its mount for the rest of its life. The lever that actually stops delivery is the external store or the `SecretProviderClass`, not this record. |
| Secret delivery into sandboxes | Experimental | `POST /v1/sandboxes` binds references via `secretRefIds`, resolved in the caller's own tenant scope at create time; unknown, foreign, revoked, duplicated, over-count, or cross-workspace bindings fail the create. The Kubernetes provider renders each binding as a read-only Secrets Store CSI volume at `/run/sandboxwich/secrets/<name>` and exposes only the path via `SANDBOXWICH_SECRET_<NAME>_FILE`, so the material is fetched by the kubelet and never enters the control plane, a Kubernetes `Secret`, or etcd. Requires an operator-configured CSI driver (`--secret-csi-driver`); provisioning is refused without one. Bindings are not inherited by forks, and a sandbox restored from a snapshot likewise starts with none — unlike `secretRefIds` on fork, which is rejected with a typed 400, snapshot restore has no field to reject, so it gives the caller no signal that the restored sandbox lacks the source's credentials. Placement is negotiated: a worker advertises `provider_secret_delivery=csi_secret_provider_class` only when its CSI driver is configured, and a secret-bound job is only claimable by such a worker, so a mixed fleet cannot dead-letter the job on an unconfigured worker. Verified against the rendered manifests only — no live-cluster CSI conformance test exists yet. |
| Billing | Unsupported | Explicit non-goal for the current milestone. |

Provider capability reports must distinguish `dry_run` from `apply`; clients
must not treat a simulated result as evidence that runtime work occurred.
Only `provider_mode=apply` is real-provider execution evidence;
`provider_mode=dry_run` is never proof that a guest process ran.

## Three sandbox timing fields, not one

`ttl_seconds`, `max_lifetime_seconds`, and `idle_ttl_seconds` are easy to
conflate because they all look like "how long does this last." They govern
three different things:

- `ttl_seconds` only starts counting once a sandbox is already `archived`
  (i.e. already stopped, by any means) and controls how long that record is
  retained before deletion. It never causes a running sandbox to stop.
- `max_lifetime_seconds` is what actually caps a *live* sandbox's total
  runtime and stops it once that cap passes.
- `idle_ttl_seconds` stops a live sandbox after a period with no observed
  activity: the most recent of its last lifecycle-state transition, its
  most recently queued guest command, and `last_activity_at` (bumped by SSH
  access, desktop access, and resident-process observation requests --
  see `crates/sandboxwich-api/src/activity.rs`).

**`create`/`fork` vs. `fork_snapshot` inheritance is intentionally
asymmetric.** `POST /sandboxes/{id}/fork` (an in-place fork) inherits the
parent's `max_lifetime_seconds`/`idle_ttl_seconds` when the request omits
them (`request.field.or(parent.field)`), then re-clamps under current
operator policy. `POST /snapshots/{id}/fork` (restoring a sandbox from a
snapshot) does **not** inherit the *source* sandbox's values at all -- only
the fork-snapshot request's own field, defaulted/clamped by the operator
config, applies. This means a caller-imposed cap on a sandbox can be shed by
snapshotting it and restoring the snapshot into a fresh sandbox with no
cap requested. It is not a loophole around *operator* policy: the
operator-configured default/ceiling
(`SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS`/`_MAX_MAX_LIFETIME_SECONDS` and
the `idle_ttl` equivalents) still applies to every `fork_snapshot` request
exactly as it does to `create`, regardless of what the source sandbox's
values were. Restoring from a snapshot is a new sandbox with a new
creation time, not a continuation of the old one, so there is no single
"parent" whose cap would be unambiguous to inherit -- unlike an in-place
fork, which has exactly one.

`POST /sandboxes/{id}/resume` is the third case, and it inherits *everything*:
it is the same sandbox, so its `max_lifetime_seconds`, `idle_ttl_seconds`,
execution class, runtime profile, and `created_at` are unchanged by the
restore. Because the hard cap is still measured from the original
`created_at`, resuming a sandbox already past that cap is rejected with
`resume_lifetime_exhausted` instead of restoring a sandbox the next reap
sweep would immediately stop again -- restore that snapshot into a new
sandbox with `POST /snapshots/{id}/fork` if a fresh clock is what you want.

See the README's "Sandbox lifetime: three separate knobs" section for the
full config surface (env vars and CLI flags).

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

A dry-run worker never advertises `virtual_machine`: a simulated provision
starts no guest, so it cannot supply a VM boundary. Only an apply-mode worker
with the `kata` profile and a nonempty RuntimeClass does. On the apply path the
provider additionally reads the admitted Pod's `spec.runtimeClassName` from the
API server and fails closed (terminal, `runtime_class_boundary_unverified`)
unless it matches the configured RuntimeClass. That read happens before a
provisioned or forked sandbox is reported ready and again before an existing
Pod is reused for a command, so no command lease runs against an unverified
boundary. `materialize_file` and the APEX instruction read still exec into an
already-verified Pod without repeating the read; they carry no execution class,
so closing that would mean caching the verified boundary per sandbox. A
rendered manifest is not evidence: a mutating webhook can strip the field.

### SW-3: what remains before `virtual_machine` can be certified

`deploy/kubernetes/kata-conformance.sh` is the gate. It provisions a real
`execution_class=virtual_machine` sandbox through the API on a Kata-capable
cluster and asserts the guest kernel differs from the node kernel, no host
processes or kubelet credentials are visible, lease/worker/API restart recovery
and out-of-band Pod deletion reach deterministic terminal states, cleanup leaks
nothing, and a worker without the `kata` profile never satisfies VM-class work.
It has no skip path.

Remaining for certification:

1. A Kata-capable disposable cluster in CI. No GitHub-hosted runner exposes
   `/dev/kvm`, so `.github/workflows/kata-conformance.yml` is manual dispatch
   against a self-hosted runner and is not a required check.
2. A green run of that workflow on a release commit, recorded here.
3. Deploy-side Kata nodes and RuntimeClass (evalops/deploy) for any
   non-disposable cluster that should serve the class.

Until 1-3 hold, the class stays Experimental regardless of the fail-closed
validation and unit coverage already in place.
