"""Typed request/response models mirroring `crates/sandboxwich-core/src/lib.rs`.

These are hand-written (not generated) to keep the SDK small. Field names,
enum wire values, and the `NetworkEgress` tagging match the Rust `serde`
representations exactly:

- Fieldless enums (`db_variant_enum!` and the explicit
  `#[serde(rename_all = "snake_case")]` enums like `OperationKind`) serialize
  as plain JSON strings, so each is modeled as a Python `str` enum.
- `NetworkEgress` is a Rust `#[serde(tag = "mode", rename_all = "snake_case")]`
  enum, i.e. internally tagged: every variant (including the unit variants
  `DenyAll`/`AllowAll`) serializes as an object carrying a `mode` field. It is
  modeled as a pydantic discriminated union on `mode`.
- `CommandOutputAnnotation` is `#[serde(tag = "type", rename_all =
  "snake_case")]`, modeled the same way.
- ID newtypes (`SandboxId`, `CommandId`, ...) are `#[serde(transparent)]`
  wrappers around a `Uuid`, so they serialize as bare UUID strings and are
  modeled directly as `uuid.UUID`.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal, Union
from uuid import UUID

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------
# Enums (wire value == Python str value; see module docstring)
# --------------------------------------------------------------------------


class SandboxState(str, Enum):
    planning = "planning"
    provisioning = "provisioning"
    ready = "ready"
    running = "running"
    idle = "idle"
    archiving = "archiving"
    archived = "archived"
    error = "error"


class WorkspaceMode(str, Enum):
    ephemeral = "ephemeral"
    generic_ephemeral = "generic_ephemeral"
    persistent = "persistent"


class MemoryLimit(str, Enum):
    """Matches `MemoryLimit`'s hand-written `Serialize` impl (plain string, not the enum name)."""

    one_g = "1g"
    four_g = "4g"
    sixteen_g = "16g"
    sixty_four_g = "64g"


class NetworkAllowRuleKind(str, Enum):
    cidr = "cidr"
    host = "host"


class CommandStatus(str, Enum):
    queued = "queued"
    running = "running"
    finished = "finished"
    failed = "failed"


class CommandOutputStream(str, Enum):
    stdout = "stdout"
    stderr = "stderr"


class SnapshotStatus(str, Enum):
    pending = "pending"
    ready = "ready"
    failed = "failed"
    expired = "expired"


class OperationKind(str, Enum):
    provision_sandbox = "provision_sandbox"
    stop_sandbox = "stop_sandbox"
    resume_sandbox = "resume_sandbox"
    run_command = "run_command"
    create_snapshot = "create_snapshot"
    fork_sandbox = "fork_sandbox"


class OperationStatus(str, Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class SandboxEventKind(str, Enum):
    lifecycle_changed = "lifecycle_changed"
    command_queued = "command_queued"
    command_started = "command_started"
    command_output = "command_output"
    command_finished = "command_finished"
    prompt_queued = "prompt_queued"
    prompt_started = "prompt_started"
    prompt_finished = "prompt_finished"
    desktop_requested = "desktop_requested"
    desktop_ready = "desktop_ready"
    desktop_failed = "desktop_failed"
    desktop_closed = "desktop_closed"
    desktop_expired = "desktop_expired"
    guest_health_failed = "guest_health_failed"
    file_uploaded = "file_uploaded"
    divergence_detected = "divergence_detected"


class JobKind(str, Enum):
    provision_sandbox = "provision_sandbox"
    stop_sandbox = "stop_sandbox"
    resume_sandbox = "resume_sandbox"
    run_command = "run_command"
    run_prompt = "run_prompt"
    create_snapshot = "create_snapshot"
    fork_sandbox = "fork_sandbox"


class JobStatus(str, Enum):
    queued = "queued"
    leased = "leased"
    succeeded = "succeeded"
    failed = "failed"
    dead = "dead"
    cancelled = "cancelled"


class WorkerCapability(str, Enum):
    provision_sandbox = "provision_sandbox"
    run_command = "run_command"
    agent_prompt = "agent_prompt"
    snapshot = "snapshot"
    desktop_stream = "desktop_stream"
    k8s_pod = "k8s_pod"
    gvisor_sandbox = "gvisor_sandbox"
    fqdn_egress = "fqdn_egress"


# --------------------------------------------------------------------------
# Network egress (internally tagged on "mode")
# --------------------------------------------------------------------------


class NetworkAllowRule(BaseModel):
    kind: NetworkAllowRuleKind
    value: str


class NetworkEgressDenyAll(BaseModel):
    mode: Literal["deny_all"] = "deny_all"


class NetworkEgressAllowlist(BaseModel):
    mode: Literal["allowlist"] = "allowlist"
    rules: list[NetworkAllowRule] = Field(default_factory=list)


class NetworkEgressAllowAll(BaseModel):
    mode: Literal["allow_all"] = "allow_all"


NetworkEgress = Annotated[
    Union[NetworkEgressDenyAll, NetworkEgressAllowlist, NetworkEgressAllowAll],
    Field(discriminator="mode"),
]


# --------------------------------------------------------------------------
# Sandboxes
# --------------------------------------------------------------------------


class Operation(BaseModel):
    id: UUID
    kind: OperationKind
    status: OperationStatus
    resource_id: UUID | None = None
    created_at: datetime
    updated_at: datetime
    error_code: str | None = None
    error_message: str | None = None


class Sandbox(BaseModel):
    id: UUID
    tenant_id: str
    name: str
    state: SandboxState
    template: str
    memory_limit: MemoryLimit
    network_egress: NetworkEgress = Field(default_factory=NetworkEgressDenyAll)
    workspace_mode: WorkspaceMode = WorkspaceMode.persistent
    created_at: datetime
    updated_at: datetime
    ttl_seconds: int | None = None
    parent_snapshot_id: UUID | None = None


class CreateSandboxRequest(BaseModel):
    name: str | None = None
    template: str | None = None
    memory_limit: MemoryLimit | None = None
    network_egress: NetworkEgress | None = None
    workspace_mode: WorkspaceMode | None = None
    ttl_seconds: int | None = None


class SandboxResponse(BaseModel):
    ok: bool
    sandbox: Sandbox
    operation: Operation | None = None


class SandboxListResponse(BaseModel):
    ok: bool
    sandboxes: list[Sandbox]
    next_cursor: str | None = None


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


class CommandRequest(BaseModel):
    argv: list[str]
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    timeout_secs: int | None = None


class CommandRun(BaseModel):
    id: UUID
    sandbox_id: UUID
    status: CommandStatus
    argv: list[str]
    cwd: str | None = None
    exit_code: int | None = None
    stdout: str
    stderr: str
    created_at: datetime
    finished_at: datetime | None = None


class CommandResponse(BaseModel):
    ok: bool
    command: CommandRun


class QueuedCommandJob(BaseModel):
    id: UUID
    sandbox_id: UUID
    command_id: UUID
    kind: JobKind
    status: JobStatus
    required_capability: WorkerCapability


class QueueCommandResponse(BaseModel):
    ok: bool
    command: CommandRun
    queued_job: QueuedCommandJob
    operation: Operation


class CommandListResponse(BaseModel):
    ok: bool
    commands: list[CommandRun]
    next_cursor: str | None = None


class ContainerFileCitation(BaseModel):
    """The only `CommandOutputAnnotation` variant today (`type = "container_file_citation"`).

    Modeled as a plain model rather than a discriminated union since pydantic
    requires at least two members for `Field(discriminator=...)`; a second
    annotation variant on the Rust side should gain a sibling model here plus
    a `Union[...]` alias with `Field(discriminator="type")`.
    """

    type: Literal["container_file_citation"] = "container_file_citation"
    file_id: UUID
    path: str
    start_index: int | None = None
    end_index: int | None = None


class CommandOutputChunk(BaseModel):
    id: UUID
    command_id: UUID
    stream: CommandOutputStream
    sequence: int
    chunk: str
    annotations: list[ContainerFileCitation] = Field(default_factory=list)
    created_at: datetime


class CommandOutputListResponse(BaseModel):
    ok: bool
    complete: bool = False
    chunks: list[CommandOutputChunk]
    next_cursor: str | None = None


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------


class SandboxFile(BaseModel):
    id: UUID
    sandbox_id: UUID
    path: str
    size_bytes: int
    mime_type: str | None = None
    created_at: datetime
    updated_at: datetime


class ListFilesResponse(BaseModel):
    ok: bool
    files: list[SandboxFile]


class FileResponse(BaseModel):
    ok: bool
    file: SandboxFile


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


class SandboxEvent(BaseModel):
    id: UUID
    sandbox_id: UUID
    kind: SandboxEventKind
    data: Any
    created_at: datetime


class EventListResponse(BaseModel):
    ok: bool
    events: list[SandboxEvent]
    next_cursor: str | None = None


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


class Snapshot(BaseModel):
    id: UUID
    sandbox_id: UUID
    status: SnapshotStatus
    label: str
    inventory: Any
    provider_metadata: Any
    created_at: datetime
    ready_at: datetime | None = None
    expires_at: datetime | None = None
    error: str | None = None


class CreateSnapshotRequest(BaseModel):
    label: str | None = None
    inventory: Any | None = None
    provider_metadata: Any | None = None
    ttl_seconds: int | None = None


class ForkSnapshotRequest(BaseModel):
    """Restores a snapshot into a brand-new sandbox (`POST /v1/snapshots/{id}/fork`).

    Unlike `CreateSandboxRequest`, `template` and `memory_limit` are required:
    the API restores directly from the durable snapshot without depending on
    the source sandbox still existing.
    """

    name: str | None = None
    template: str
    memory_limit: MemoryLimit
    network_egress: NetworkEgress = Field(default_factory=NetworkEgressDenyAll)
    ttl_seconds: int | None = None


class SnapshotResponse(BaseModel):
    ok: bool
    snapshot: Snapshot
    operation: Operation | None = None


class SnapshotListResponse(BaseModel):
    ok: bool
    snapshots: list[Snapshot]
    next_cursor: str | None = None


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------


class HealthComponent(BaseModel):
    ok: bool
    message: str | None = None


class HealthResponse(BaseModel):
    ok: bool
    service: str
    checked_at: datetime
    database: HealthComponent | None = None


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ErrorEnvelope(BaseModel):
    """The stable `{ "ok": false, "code", "message" }` error body documented in README.md."""

    ok: bool = False
    code: str
    message: str
