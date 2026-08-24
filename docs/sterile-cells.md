# One-shot sterile cells

Sterile cells are disabled unless the API process has both settings:

```text
SANDBOXWICH_STERILE_CELLS_ENABLED=true
SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE=/run/secrets/sterile-cell-signing-key
```

When disabled, the existing sandbox creation and resident-process paths keep
their previous behavior. Sterile-cell routes return `404`.

## Purpose-created pool

The API creates no pool members unless `SANDBOXWICH_STERILE_POOL_TARGET` is
greater than zero and these values are set:

```text
SANDBOXWICH_STERILE_POOL_TENANT_ID
SANDBOXWICH_STERILE_POOL_RELEASE_SET_ID
SANDBOXWICH_STERILE_POOL_RUNTIME_CLASS
SANDBOXWICH_STERILE_POOL_POLICY_DIGEST
SANDBOXWICH_STERILE_POOL_RELEASE_SIGNATURE
SANDBOXWICH_STERILE_POOL_SANDBOX_PROFILE
SANDBOXWICH_STERILE_POOL_TEMPLATE
SANDBOXWICH_STERILE_POOL_AGENT_IMAGE
SANDBOXWICH_STERILE_POOL_MAESTRO_IMAGE
```

`SANDBOXWICH_STERILE_POOL_READY_FLOOR` defaults to `0` and protects that
many ready cells from pool claims. `SANDBOXWICH_STERILE_POOL_MAX_PROVISIONING`
defaults to the target and caps the number of pool members that may be in
`provisioning` at once. The target must be at least the ready floor, and the
maximum provisioning value must be greater than zero and no greater than the
target.

`SANDBOXWICH_STERILE_POOL_READY_TTL_SECONDS` defaults to `300`. Its clock
starts when provider provisioning completes. The configured release signature
must validate under `SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE`, and the pool
provider preference is fixed to Kubernetes. Both candidate images must use an
exact lowercase `@sha256:<64 hex>` digest; there is no generic runtime-image
fallback. Pool workspaces are Persistent one-shot PVCs. This repository
contains no production pool values.

Pool membership is stored by `sandbox_id`. The sandbox ID, sterile cell ID,
and provider cell ID are identical. Provision completion inserts the ready
cell and records its worker placement in one database transaction. A claim
is serialized with reconciliation by a durable controller lock and cannot
consume the last `ready_floor` matching pool members. Reconciliation counts
`provisioning`, `ready`, `leased`, `stopping`, and `cleanup_pending` members
against the hard target, and creates at most
`min(target - live_count, max_provisioning - provisioning_count)` replacements.
Leased or stopping members therefore remain part of capacity until provider
cleanup is confirmed.

Pool sandboxes and their jobs are absent from ordinary tenant list, read, and
mutation routes for the lifetime of their durable membership. Sterile
activation uses the exact lease ID and generation lookup instead. The
Kubernetes pod receives `SANDBOXWICH_STERILE_POOL_CANDIDATE_V1`, whose JSON
value contains the cell ID, signed release tuple, digest-pinned agent and
Maestro images, and stable Service name. Scheduler enrichment derives this
non-secret value from pool membership. Admission records the exact Pod name
and UID reported at the provider's `pod_ready` stage before the cell becomes
ready.

## Signed trust class

A ready cell is admitted under this exact tuple:

```text
release_set_id
runtime_class = kata_microvm | gvisor_lower_risk
policy_digest = 64 lowercase hexadecimal characters
```

`kata_microvm` is the VM-equivalent class. `gvisor_lower_risk` is a separate
class for workloads whose threat model permits a shared host kernel. A claim
for either class cannot consume inventory from the other class.

The release signature is HMAC-SHA256 under the configured signing key. The
file must be a mounted Secret containing at least 32 bytes. Its value never
belongs in an environment variable or command-line argument.

The release signature uses that signing key. Its canonical message is:

```text
sandboxwich-sterile-release-v1\0<release_set_id>\0<runtime_class>\0<lowercase-policy_digest>
```

The wire value is `swrs1_` followed by unpadded base64url MAC bytes. The API
verifies the signature on prepare and claim. Workers must advertise
`virtual_machine` for `kata_microvm` and `sandboxed_container` for
`gvisor_lower_risk`.

## State and database fences

The durable row starts at generation `1` in `ready`. An atomic claim changes it
to `leased`, increments the generation, records the tenant and exact
organization/workspace/thread/runner-session tuple, and stores only the
SHA-256 hash of the returned lease attestation. A separate tenant-scoped claim
row records the client-generated `claim_id`, a digest of the exact claim
request (including the requested TTL semantics), and a non-secret lease
locator. It never stores raw attestation bytes.

The normal transition sequence is:

```text
ready(generation=1, never exposed)
  -> leased(generation=2, tenant exposed)
  -> destroyed
```

`quarantined` is terminal for cell authority. Pool membership remains
`cleanup_pending` after a failed, expired, or ambiguous stop until the
controller queues another placed provider stop under the recorded fence. This
cleanup reconciler runs after API restart even when the configured pool target
is zero. Only provider-confirmed completion terminalizes pool membership. No
route transitions `leased`, `destroyed`, or `quarantined` back to `ready`. The
database primary key also prevents a destroyed cell ID from being prepared
again.

Workers must delete the child container or microVM, its overlay, and its
runtime namespace before reporting `destroyed`. If deletion cannot be proven,
they report `quarantined`. Tenant-exposed runtime objects cannot be registered
as new cells under another ID.

## HTTP contract

All endpoints are available under `/v1`; unversioned aliases follow the rest of
the Sandboxwich API.

| Caller | Endpoint | Result |
| --- | --- | --- |
| Worker token | `POST /workers/{worker_id}/sterile-cells/prepare` | Registers a never-used provider cell under a signed trust class. |
| Worker token | `GET /workers/{worker_id}/sterile-cells/{cell_id}` | Reconciles an ambiguous prepare or claim response with the cell and an optional non-secret claim locator. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/retire` | Quarantines an unexposed `ready(generation=1)` cell under an exact generation fence. |
| Tenant token | `POST /sterile-cells/claim` | Atomically leases one exact matching cell. Fenced claims durably record an empty result and its diagnosis; legacy unfenced claims retain the original one-shot behavior. |
| Tenant, worker, or guest token plus lease attestation | `POST /sterile-cell-leases/{lease_id}/validate` | Returns the live tuple only when token, tenant, generation, tuple, state, and expiry match. |
| Tenant token | `POST /sterile-cell-leases/{lease_id}/release` | Accepts provider teardown under the exact attestation, generation, and organization/workspace/thread/session tuple; returns `202` while teardown runs. |
| Tenant token | `GET /sterile-cell-leases/{lease_id}` | Returns the tenant-scoped cell ID, lease ID, generation, state, and disposition without provider locators or attestation data. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/destroy` | Records proven destruction or quarantine under the exact lease generation. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/release` | Controller-only release trigger for a pool-created cell. |

New controllers supply the optional UUID `claim_id`. While its lease remains
live, an exact fenced retry returns the same lease and deterministically
regenerates the same `lease_attestation`; reuse with any different release,
binding, or requested TTL fails with `409`. A retry of a durably empty fenced
claim stays empty with the same diagnosis, even if inventory arrives later.
Exhausted fenced claim contention is a non-success `409`, so callers retry the
same fence instead of treating an unfenced empty response as authoritative.
Expired or terminal leases never regenerate authority.

A successful claim has `ok: true`, a lease, and an attestation. An empty claim
keeps the V1-compatible HTTP `200` and nullable lease fields, but has `ok:
false`, a typed `no_lease_reason`, and tenant-scoped aggregate `claimability`
evidence. Reasons distinguish absent capacity, a release mismatch, unhealthy
pool-ready reports, already-leased capacity, ready-floor protection, mixed
non-claimability, and legacy unfenced contention. Evidence reports only counts
of pool-ready, unhealthy pool-ready, ready, claimable, protected, leased, and
mismatched active cells. It contains no cell, worker, provider, lease, tenant,
or attestation locators. Successful responses omit both diagnosis fields so
existing clients retain their original response shape.

For V1 compatibility, omitting `claim_id` retains the original unfenced,
one-shot semantics: each request is a new claim attempt, including after an
ambiguous response. New controller integrations must send a fence; the legacy
form exists only so already-deployed clients continue to deserialize and call
the V1 route unchanged.

The token is HMAC-bound to cell ID, lease ID, generation, signed release tuple,
organization, workspace, thread, runner session, and expiry. Its maximum TTL
is 300 seconds. Only its SHA-256 digest is persisted. Worker lookup exposes
`claim_id`, `lease_id`, generation, and expiry, but never the raw token or its
digest.

## Worker and agent integration

The worker binary exposes `sterile-prepare`, `sterile-claim`, and
`sterile-destroy` actions for the three lifecycle calls. The worker-scoped
token is required for prepare, lookup, ready-cell retirement, and destroy.
Platform uses its tenant-scoped token for claim. `sterile-claim` requires an
explicit `--claim-id` so retries can reuse the same fence. It also requires
`--attestation-output-file`. The command creates that file with mode `0600`
and fails if the path already exists. Standard output contains the lease
locator and redacted metadata; it never contains the raw attestation.

The legacy direct-start path supplies the claim fields and raw attestation
through a read-only file. Configure the agent daemon with:

```text
SANDBOXWICH_STERILE_LEASE_ID
SANDBOXWICH_STERILE_LEASE_GENERATION
SANDBOXWICH_STERILE_LEASE_ATTESTATION_FILE
SANDBOXWICH_STERILE_ORGANIZATION_ID
SANDBOXWICH_STERILE_WORKSPACE_ID
SANDBOXWICH_STERILE_THREAD_ID
SANDBOXWICH_STERILE_RUNNER_SESSION_ID
```

If one value is present, all seven are required. The daemon validates the
lease through Sandboxwich before its first ready heartbeat or lease claim.
Attestation bytes do not go on argv or into provider metadata.

## Resident activation

Resident activation has a separate feature flag and is disabled by default:

```text
SANDBOXWICH_STERILE_RESIDENT_ACTIVATION_ENABLED=true
SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY=<standard-base64-encoded-32-byte-key>
```

The shared handoff key is mandatory when resident activation is enabled, and
must be identical on every API replica. Startup fails closed if the flag is on
without the key.

A resident request may include `sterileActivation` with the lease ID,
generation, exact organization/workspace/thread/runner-session tuple, and raw
attestation. The sandbox ID must equal the purpose-created cell ID. Admission
checks the live leased cell, tenant, tuple, attestation hash, and expiry in the
resident insert transaction. That transaction binds one resident process ID
and generation to the cell. A different resident identity receives `409`.

The resident row and queued job contain only the cell ID, lease ID, and lease
generation. The API keeps the raw attestation in the bounded in-memory
bootstrap store or in its encrypted shared handoff. An activation without a
file bootstrap uses a zero-byte internal handoff; its resident row has no
bootstrap target or mode. The agent reads the handoff under the active job
lease, validates the raw attestation immediately before bootstrap preparation
and each process spawn, and rejects an expired or mismatched lease. A stale
queued activation is marked dead and its cell is quarantined during claim so
it cannot block later jobs.

Purpose-created prewarmed agents receive the immutable non-secret
`SANDBOXWICH_STERILE_POOL_CANDIDATE_V1` marker. Its JSON contains the cell ID
and signed release tuple. The release signature carries no secret key material.
Candidate control agents accept only the exact gated Maestro resident job for
that cell, release, lease, tenant, bound resident generation, and Pod identity.
Agents without the marker reject gated jobs, and candidate agents reject
ungated jobs. The raw lease attestation is never placed in this marker, an
environment variable, argv, a job, provider metadata, or a log entry.

The prewarmed Pod separates authority from tenant execution. A trusted
`sandboxwich-control` sidecar owns the guest credential, claims the fenced job,
reads the one-shot encrypted bootstrap, and revalidates the lease immediately
before sending the sanitized activation to the credential-free
`sterile-launcher` over a dedicated mTLS HTTP channel. The launcher accepts one
exact activation, returns the same in-memory status for an exact retry after a
lost response, and rejects a conflicting retry. No activation or status file
is written. The raw lease attestation remains in the control sidecar and never
crosses the channel. The launcher rechecks the immutable marker, exact Pod
identity, fence, and fresh expiry, writes the gateway token file, and only then
spawns Maestro. The Maestro container has no API or guest-token environment
variable or mount, and the Pod does not share a process namespace.

The seven startup settings remain available for the legacy direct-start mode.
Prewarmed pool agents start before a lease exists and therefore use the
immutable candidate marker plus the resident activation handoff. They receive
no post-start environment injection.

## Platform request sequence

1. Select the release set, runtime class, and policy digest required by the
   thread.
2. Generate a UUID claim fence and call `POST /v1/sterile-cells/claim` with
   `claim_id` and the tenant-authenticated tuple. Reuse that ID and the exact
   body after an ambiguous response.
3. When `lease` is null, use the existing cold sandbox path.
4. Put the resident process with `sterileActivation`. The API transfers the
   raw attestation through the resident bootstrap handoff.
5. Permit tenant bootstrap only after the agent's validation call succeeds.
6. After execution, call `POST /v1/sterile-cell-leases/{lease_id}/release`
   with the exact attestation, generation, tuple, and requested disposition.
7. Poll `GET /v1/sterile-cell-leases/{lease_id}` until `providerAbsent` is
   true. `cleanupPending` is true only while durable pool membership needs a
   provider cleanup retry; neither boolean is inferred from the cell state.
   Only an exactly fenced completed `StopSandbox` records provider absence.
   until an exact provider retry succeeds. Exact completion replays are
   idempotent.
8. If prepare is ambiguous, use the worker lookup before retrying registration.
   If an unclaimed ready cell must be removed, delete its provider resources
   and call `retire` with generation `1`; retirement only records
   `quarantined`, never proven `destroyed`.

Cloudflare Workers are not required by this contract. A regional gateway can
call the versioned Sandboxwich API directly and retain the existing cold path
as its feature-flag fallback.
