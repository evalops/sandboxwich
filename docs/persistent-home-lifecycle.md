# Persistent Home Lifecycle Contract

Sandboxwich managed homes provide durable workspace storage across sandbox
replacement. This document defines the mount ownership and API behavior that
callers must use when more than one request can resolve or create the same
logical home.

## Invariant And Authority

One durable home has at most one live sandbox. Sandboxwich owns and enforces
that invariant with the durable `sandbox_home_mounts` record and its unique
home constraint. A caller-side cache or read-before-create check is not an
exclusivity boundary.

`POST /v1/homes` accepts a stable `external_key` and returns the existing home
when that key already exists for the tenant. Both that response and
`GET /v1/homes/{home_id}` include the authoritative `mounted_sandbox`, when
present:

```json
{
  "mounted_sandbox": {
    "sandbox_id": "...",
    "sandbox_state": "planning"
  }
}
```

The mount is claimed in the same transaction that creates the `planning`
sandbox and its provisioning job. Concurrent claims cannot both succeed.

## Mount State Semantics

| `mounted_sandbox.sandbox_state` | Caller contract |
| --- | --- |
| no mount | Create one persistent sandbox with `POST /v1/homes/{home_id}/sandboxes`. |
| `planning`, `provisioning` | The mount is live and provisioning. Wait for this sandbox, then adopt it. Do not create another. |
| `ready`, `running`, `idle` | The mount is live and usable. Adopt or reuse this sandbox. |
| `archiving` | The mount is still live and teardown owns it. Wait for `archived` or detachment; never start a replacement yet. |
| `archived`, `error` | The sandbox is replacement-eligible. A create may lazily remove the stale terminal mount and claim the home for a new sandbox in one transaction. |
| unknown | Fail closed and preserve the identity and state for diagnosis. |

The exported generic lifecycle contract labels `archiving` as terminal because
it cannot return to a usable state. That label does not mean the provider has
released the mount or runtime resources. Normal stop completion moves
`archiving` to `archived` only after provider-confirmed teardown and releases
the mount. This narrower home-ownership contract takes precedence when deciding
whether replacement is safe.

`archived` and `error` mount rows can remain visible until a later create
performs lazy release. Their presence in a home read is intentional: callers
see the same authoritative row that the next claim must reconcile.

## Typed Conflict Recovery

A concurrent loser of the home mount claim receives:

```http
HTTP/1.1 409 Conflict

{"ok":false,"code":"home_already_mounted","message":"home already has a live sandbox"}
```

This conflict means “observe the winner,” not “repeat the POST”:

1. Re-read `GET /v1/homes/{home_id}`.
2. Apply the mount state table to the returned sandbox identity.
3. Adopt a usable winner, wait for a pending or archiving winner, or make one
   bounded replacement attempt only after `archived`, `error`, or detachment.

Callers must branch on both HTTP status and the stable error `code`. Other 409
codes, including `idempotency_key_reused`, `idempotency_in_progress`, and
`home_not_ready`, have different recovery contracts. Treating every 409 as a
mounted-home race or blindly retrying the same POST can create a conflict
storm and hide the actual contract violation.

A lost create response uses the same recovery path: read the home and reconcile
its mount. The durable mount decides the winner.

## Ownership Across The Platform Integration

| Component | Responsibility |
| --- | --- |
| Sandboxwich | Durable home identity, exclusive mount claim, sandbox lifecycle state, terminal-mount release, and typed API errors. |
| Tool Executor | Caller orchestration: resolve the home, adopt or wait for the mounted sandbox, and reconcile create races. |
| Runner Host | Runtime readiness for the selected runner session. It does not own managed-home exclusivity. |
| Maestro | May consume the selected runtime outcome. It does not arbitrate the home mount or replacement. |

The consumer-side algorithm and operational symptom map live in Platform's
[Tool Executor contract](https://github.com/evalops/platform/blob/main/docs/services/tool-executor/persistent-home-lifecycle.md).

## Operational Diagnosis

For one incident, correlate the tenant scope, home external key and ID, mounted
sandbox ID and state, request ID, HTTP status, and typed error code. Do not log
bearer tokens, guest credentials, or workspace contents.

- Repeated `home_already_mounted` responses with repeated creates indicate a
  caller that is not re-reading and adopting or waiting for the winner.
- A mount stuck in `planning` or `provisioning` is a provisioning problem on
  that sandbox, not permission to create a competitor.
- A mount stuck in `archiving` is a teardown or provider-cleanup problem. The
  home is not replacement-safe yet.
- A usable mount with a later runtime failure has already converged on
  exclusivity; diagnose caller session registration or runtime readiness.
- An `archived` or `error` row is replacement-eligible, but any conflict from
  that replacement still requires a fresh home read to discover the winner.
