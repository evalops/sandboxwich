"""Thin typed Python client for the sandboxwich control plane.

    from sandboxwich import SandboxwichClient

    with SandboxwichClient("http://127.0.0.1:3217") as client:
        created = client.create_sandbox(name="demo")
        sandbox = client.wait_for_sandbox_ready(created.sandbox.id)

See sdks/python/README.md for the full quickstart and sdks/python/examples/
for runnable scripts.
"""

from .client import SandboxwichClient
from .errors import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    RateLimitedError,
    SandboxwichConnectionError,
    SandboxwichError,
    SandboxwichTimeoutError,
    ServerError,
    UnauthorizedError,
    UnsupportedError,
)
from .models import (
    CommandOutputChunk,
    CommandOutputStream,
    CommandRequest,
    CommandResponse,
    CommandRun,
    CommandStatus,
    CreateSandboxRequest,
    CreateSnapshotRequest,
    ForkSnapshotRequest,
    MemoryLimit,
    NetworkAllowRule,
    NetworkAllowRuleKind,
    NetworkEgress,
    NetworkEgressAllowAll,
    NetworkEgressAllowlist,
    NetworkEgressDenyAll,
    Sandbox,
    SandboxEvent,
    SandboxResponse,
    SandboxState,
    Snapshot,
    SnapshotResponse,
    WorkspaceMode,
)

__all__ = [
    "SandboxwichClient",
    "SandboxwichError",
    "BadRequestError",
    "UnauthorizedError",
    "NotFoundError",
    "ConflictError",
    "UnsupportedError",
    "RateLimitedError",
    "ServerError",
    "SandboxwichConnectionError",
    "SandboxwichTimeoutError",
    "Sandbox",
    "SandboxResponse",
    "SandboxState",
    "SandboxEvent",
    "CreateSandboxRequest",
    "MemoryLimit",
    "WorkspaceMode",
    "NetworkEgress",
    "NetworkEgressDenyAll",
    "NetworkEgressAllowlist",
    "NetworkEgressAllowAll",
    "NetworkAllowRule",
    "NetworkAllowRuleKind",
    "CommandRequest",
    "CommandRun",
    "CommandResponse",
    "CommandStatus",
    "CommandOutputChunk",
    "CommandOutputStream",
    "Snapshot",
    "SnapshotResponse",
    "CreateSnapshotRequest",
    "ForkSnapshotRequest",
]

__version__ = "0.1.0"
