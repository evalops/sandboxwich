# Roadmap

This roadmap is ordered to keep the product honest: durable control-plane contracts first, then worker ownership, then real guest execution, then snapshots, desktop access, and provider backends.

## Milestone 1: Control Plane Foundation

Goal: make the API state model durable, portable, and testable enough for workers to trust it.

- Prove lifecycle and event contracts with integration tests.
- Keep SQLite for local development and Postgres for shared deployments.
- Add command lookup and list APIs beyond the immediate queue response.
- Add schema constraints for sandbox states, event kinds, and command statuses.
- Persist runtime resources as typed database rows instead of provider JSON blobs.

## Milestone 2: Worker Leases

Goal: let workers safely claim, renew, finish, and retry work through durable leases.

- Add worker registration and heartbeat records.
- Implement a durable lease queue for sandbox and command work.
- Add lease timeout, retry, and ownership transitions.
- Wire `sandboxwich-worker` to claim and report jobs.
- Use typed worker completion results so job outcomes are matched by contract, not JSON shape.

## Milestone 3: Guest Agent Execution

Goal: replace dry-run command responses with real command lifecycle events from guests.

- Define the guest-agent protocol for command start, output, exit, and failure.
- Stream command output into control-plane events.
- Add SSH key injection lifecycle.
- Add failure semantics for unhealthy or unreachable guests.
- Ship daemon-mode guest agent execution with streaming stdout/stderr chunks.
- Add guest file upload, download, list, and file-citation annotations.

## Milestone 4: Snapshot And Fork

Goal: represent snapshot provenance explicitly before provider-specific implementation details leak into the API.

- Add snapshot records and inventory APIs.
- Replace synthetic fork provenance with real snapshot records.
- Add fork planning and state transitions.
- Add retention and TTL cleanup for snapshots and archived sandboxes.

## Milestone 5: Desktop Access

Goal: add a brokered desktop-session contract without exposing long-lived secrets.

- Define desktop readiness and connection metadata.
- Add a desktop stream broker service boundary.
- Emit desktop availability events from workers or providers.
- Add CLI/API commands for desktop session discovery.

## Milestone 6: Provider Backends

Goal: make providers pluggable and testable before wiring real infrastructure.

- Define provider adapter traits and capability reports.
- Implement the first VM or microVM adapter.
- Add RuntimeClass-backed isolation for gVisor/Kata-capable Kubernetes clusters.
- Add resource tiers and network egress policy to provisioning specs.
- Add provider health and capability reporting.
- Add an end-to-end provision, exec, snapshot, and fork smoke test.

## Non-Goals For Now

- Billing.
- Production secret storage.
- Direct cloud mutations from tests.
- User-visible claims of real isolation before a provider backend exists.
