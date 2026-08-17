# Documentation

The root [README](../README.md) contains the local quick start, configuration
reference, API overview, and development commands.

## Operational guides

- [Capability matrix](capabilities.md): Provider status and evidence.
- [Kubernetes deployment](kubernetes.md): Manifests, RBAC, apply mode,
  storage, and egress.
- [Persistent home lifecycle](persistent-home-lifecycle.md): Home ownership,
  stop, resume, cleanup, and races.
- [Sterile-cell contract](sterile-cells.md): Warm-cell leases, attestation,
  and cleanup.
- [Performance harness](perf-harness.md): Performance commands and A/B
  verdicts.
- [Repository rules](repository-rules.md): Main ruleset and required-check
  validation.

## Versioned contracts

- [HTTP OpenAPI contract](../contracts/openapi.v1.json)
- [Authorization conformance cases](authorization/authz-conformance.v1.json)

The dated files under [`superpowers/`](superpowers/) are design specs and
implementation plans. They describe decisions and planned work; the capability
matrix and versioned contracts describe the current supported surface.
