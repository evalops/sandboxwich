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
```

`SANDBOXWICH_STERILE_POOL_READY_TTL_SECONDS` defaults to `300`. Its clock
starts when provider provisioning completes. The configured release signature
must validate under `SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE`, and the pool
provider preference is fixed to Kubernetes. This repository contains no
production pool values.

Pool membership is stored by `sandbox_id`. The sandbox ID, sterile cell ID,
and provider cell ID are identical. Provision completion inserts the ready
cell and records its worker placement in one database transaction. A claim
removes that member from the reserve count, so the next reconcile creates one
replacement.

Pool sandboxes and their jobs are absent from ordinary tenant list, read, and
mutation routes for the lifetime of their durable membership. Sterile
activation uses the exact lease ID and generation lookup instead. The
Kubernetes pod receives `SANDBOXWICH_STERILE_POOL_CANDIDATE_V1`, whose JSON
value contains the cell ID and signed release tuple. Scheduler enrichment
derives this value from pool membership.

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
| Tenant token | `POST /sterile-cells/claim` | Atomically leases one exact matching cell. Fenced claims durably record `lease: null`; legacy unfenced claims retain the original one-shot behavior. |
| Tenant, worker, or guest token plus lease attestation | `POST /sterile-cell-leases/{lease_id}/validate` | Returns the live tuple only when token, tenant, generation, tuple, state, and expiry match. |
| Tenant token | `POST /sterile-cell-leases/{lease_id}/release` | Accepts provider teardown under the exact attestation, generation, and organization/workspace/thread/session tuple; returns `202` while teardown runs. |
| Tenant token | `GET /sterile-cell-leases/{lease_id}` | Returns the tenant-scoped cell ID, lease ID, generation, state, and disposition without provider locators or attestation data. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/destroy` | Records proven destruction or quarantine under the exact lease generation. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/release` | Controller-only release trigger for a pool-created cell. |

New controllers supply the optional UUID `claim_id`. While its lease remains
live, an exact fenced retry returns the same lease and deterministically
regenerates the same `lease_attestation`; reuse with any different release,
binding, or requested TTL fails with `409`. A retry of a durably empty fenced
claim stays empty, even if inventory arrives later. Exhausted fenced claim
contention is a non-success `409`, so callers retry the same fence instead of
treating an unfenced empty response as authoritative. Expired or terminal
leases never regenerate authority.

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
explicit `--claim-id` so retries can reuse the same fence.

The sterile child receives the claim fields and raw attestation through a
read-only file. Configure the agent daemon with:

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

## Platform request sequence

1. Select the release set, runtime class, and policy digest required by the
   thread.
2. Generate a UUID claim fence and call `POST /v1/sterile-cells/claim` with
   `claim_id` and the tenant-authenticated tuple. Reuse that ID and the exact
   body after an ambiguous response.
3. When `lease` is null, use the existing cold sandbox path.
4. Deliver the returned attestation to the leased child through a read-only
   file and pass the six non-secret fence values as environment variables.
5. Permit tenant bootstrap only after the agent's validation call succeeds.
6. After execution, call `POST /v1/sterile-cell-leases/{lease_id}/release`
   with the exact attestation, generation, tuple, and requested disposition.
7. Poll `GET /v1/sterile-cell-leases/{lease_id}` until it reports `destroyed`
   or `quarantined`. Only a completed `StopSandbox` provider job records
   `destroyed`; a failed job revokes cell authority and remains cleanup-pending
   until an exact provider retry succeeds. Exact completion replays are
   idempotent.
8. If prepare is ambiguous, use the worker lookup before retrying registration.
   If an unclaimed ready cell must be removed, delete its provider resources
   and call `retire` with generation `1`; retirement only records
   `quarantined`, never proven `destroyed`.

Cloudflare Workers are not required by this contract. A regional gateway can
call the versioned Sandboxwich API directly and retain the existing cold path
as its feature-flag fallback.
