# One-shot sterile cells

Sterile cells are disabled unless the API process has both settings:

```text
SANDBOXWICH_STERILE_CELLS_ENABLED=true
SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE=/run/secrets/sterile-cell-signing-key
```

When disabled, the existing sandbox creation and resident-process paths keep
their previous behavior. Sterile-cell routes return `404`.

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

The release signature is HMAC-SHA256 under
The file must be a mounted Secret containing at least 32 bytes. Its value never belongs in an environment variable or command-line argument.

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
SHA-256 hash of the returned lease attestation.

The normal transition sequence is:

```text
ready(generation=1, never exposed)
  -> leased(generation=2, tenant exposed)
  -> destroyed
```

`quarantined` is terminal. Expired ready cells, expired leases, stale cleanup
generations, and cleanup requests whose lease fence does not match enter that
state. No route transitions `leased`, `destroyed`, or `quarantined` back to
`ready`. The database primary key also prevents a destroyed cell ID from being
prepared again.

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
| Tenant token | `POST /sterile-cells/claim` | Atomically leases one exact matching cell or returns `lease: null`. |
| Tenant, worker, or guest token plus lease attestation | `POST /sterile-cell-leases/{lease_id}/validate` | Returns the live tuple only when token, tenant, generation, tuple, state, and expiry match. |
| Worker token | `POST /workers/{worker_id}/sterile-cells/{cell_id}/destroy` | Records proven destruction or quarantine under the exact lease generation. |

The claim response contains the only copy of `lease_attestation`. The token is
HMAC-bound to cell ID, lease ID, generation, signed release tuple,
organization, workspace, thread, runner session, and expiry. Its maximum TTL is
300 seconds.

## Worker and agent integration

The worker binary exposes `sterile-prepare`, `sterile-claim`, and
`sterile-destroy` actions for the three lifecycle calls. The worker-scoped
token is required for prepare and destroy. Platform uses its tenant-scoped
token for claim.

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
2. Call `POST /v1/sterile-cells/claim` with the tenant-authenticated tuple.
3. When `lease` is null, use the existing cold sandbox path.
4. Deliver the returned attestation to the leased child through a read-only
   file and pass the six non-secret fence values as environment variables.
5. Permit tenant bootstrap only after the agent's validation call succeeds.
6. After execution, delete every provider object for the child and call the
   destroy endpoint with the lease ID and generation.
7. Submit `quarantined` when cleanup evidence is incomplete. Do not return the
   cell to inventory.

Cloudflare Workers are not required by this contract. A regional gateway can
call the versioned Sandboxwich API directly and retain the existing cold path
as its feature-flag fallback.
