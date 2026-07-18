"""Sync HTTP client for the sandboxwich control plane.

Mirrors the canonical flows in `crates/sandboxwich-cli/src/main.rs`: create /
list / get / stop / resume / fork a sandbox, queue a command and poll or
stream its output (respecting `CommandOutputChunk.sequence`), upload/list/
download files, list events, and create/list/get/restore snapshots.

Auth: pass `api_token` explicitly, or set `SANDBOXWICH_API_TOKEN` in the
environment. The token is only ever sent as an `Authorization: Bearer ...`
header -- never placed on a command line or logged.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx
from pydantic import BaseModel

from .errors import (
    SandboxwichConnectionError,
    SandboxwichError,
    SandboxwichTimeoutError,
    error_for_response,
)
from .models import (
    CommandListResponse,
    CommandOutputChunk,
    CommandOutputListResponse,
    CommandRequest,
    CommandResponse,
    CommandRun,
    CommandStatus,
    CreateSandboxRequest,
    CreateSnapshotRequest,
    ErrorEnvelope,
    EventListResponse,
    FileResponse,
    ForkSnapshotRequest,
    HealthResponse,
    ListFilesResponse,
    MemoryLimit,
    NetworkEgress,
    NetworkEgressDenyAll,
    QueueCommandResponse,
    Sandbox,
    SandboxListResponse,
    SandboxResponse,
    SandboxState,
    SnapshotListResponse,
    SnapshotResponse,
    WorkspaceMode,
)

DEFAULT_BASE_URL = "http://127.0.0.1:3217"
DEFAULT_TIMEOUT = 30.0

_TERMINAL_COMMAND_STATES = frozenset({CommandStatus.finished, CommandStatus.failed})

_IDEMPOTENCY_KEY_HEADER = "idempotency-key"


class SandboxwichClient:
    """A thin synchronous client. One instance per tenant/token; not thread-safe
    beyond what the underlying `httpx.Client` already guarantees."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        api_token: str | None = None,
        tenant: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> None:
        token = api_token if api_token is not None else os.environ.get("SANDBOXWICH_API_TOKEN")
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if tenant:
            headers["x-sandboxwich-tenant"] = tenant

        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "SandboxwichClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # ----------------------------------------------------------------
    # Low-level request plumbing
    # ----------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        mutating: bool = False,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        headers = kwargs.pop("headers", {}) or {}
        if mutating:
            # A fresh key per call only makes *this* request server-side
            # replayable; pass idempotency_key explicitly to make a retried
            # Python-level call replay instead of re-executing the mutation
            # (mirrors the CLI's --idempotency-key).
            headers[_IDEMPOTENCY_KEY_HEADER] = idempotency_key or str(uuid.uuid4())
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            response = self._client.request(
                method,
                path,
                json=json_body,
                params=clean_params or None,
                headers=headers,
                **kwargs,
            )
        except httpx.TimeoutException as error:
            raise SandboxwichTimeoutError(str(error)) from error
        except httpx.ConnectError as error:
            raise SandboxwichConnectionError(str(error)) from error
        if response.status_code >= 400:
            raise self._error_from_response(response)
        return response

    def _error_from_response(self, response: httpx.Response) -> SandboxwichError:
        request_id = response.headers.get("x-request-id")
        retry_after_header = response.headers.get("retry-after")
        retry_after = int(retry_after_header) if retry_after_header and retry_after_header.isdigit() else None
        code: str | None = None
        message = response.text
        body: ErrorEnvelope | None = None
        try:
            body = ErrorEnvelope.model_validate(response.json())
            code = body.code
            message = body.message
        except Exception:
            pass
        return error_for_response(
            response.status_code,
            code=code,
            message=message,
            request_id=request_id,
            body=body,
            retry_after=retry_after,
        )

    @staticmethod
    def _dump(model: BaseModel) -> dict[str, Any]:
        return model.model_dump(mode="json", exclude_none=True)

    # ----------------------------------------------------------------
    # Sandboxes
    # ----------------------------------------------------------------

    def create_sandbox(
        self,
        *,
        name: str | None = None,
        template: str | None = None,
        memory_limit: MemoryLimit | None = None,
        network_egress: NetworkEgress | None = None,
        workspace_mode: WorkspaceMode | None = None,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> SandboxResponse:
        """`POST /v1/sandboxes`. Returns HTTP 202: the sandbox starts in `Planning`.

        Use `wait_for_sandbox_ready` to block until it reaches `Ready`/`Error`/`Archived`.
        """
        request = CreateSandboxRequest(
            name=name,
            template=template,
            memory_limit=memory_limit,
            network_egress=network_egress,
            workspace_mode=workspace_mode,
            ttl_seconds=ttl_seconds,
        )
        response = self._request(
            "POST",
            "/v1/sandboxes",
            json_body=self._dump(request),
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SandboxResponse.model_validate(response.json())

    def list_sandboxes(
        self,
        *,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> SandboxListResponse:
        """`GET /v1/sandboxes`, keyset-paginated via `next_cursor` (see README's
        "Public API contract"). Pass the previous response's `next_cursor` as `after`."""
        response = self._request(
            "GET",
            "/v1/sandboxes",
            params={"limit": limit, "after": after, "before": before},
        )
        return SandboxListResponse.model_validate(response.json())

    def get_sandbox(self, sandbox_id: uuid.UUID | str) -> SandboxResponse:
        response = self._request("GET", f"/v1/sandboxes/{sandbox_id}")
        return SandboxResponse.model_validate(response.json())

    def stop_sandbox(
        self, sandbox_id: uuid.UUID | str, *, idempotency_key: str | None = None
    ) -> SandboxResponse:
        """`POST /v1/sandboxes/{id}/stop`. Returns HTTP 202; the sandbox moves to
        `Archiving` immediately and `Archived` once the provider confirms teardown."""
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/stop",
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SandboxResponse.model_validate(response.json())

    def resume_sandbox(
        self, sandbox_id: uuid.UUID | str, *, idempotency_key: str | None = None
    ) -> SandboxResponse:
        """`POST /v1/sandboxes/{id}/resume`.

        Included for CLI parity, but per docs/capabilities.md ("True resume
        after teardown": Unsupported) the API currently always returns a
        typed `501 unsupported` (raised here as `UnsupportedError`) -- stop
        destroys resources, so create or fork a replacement instead.
        """
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/resume",
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SandboxResponse.model_validate(response.json())

    def fork_sandbox(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        name: str | None = None,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> SandboxResponse:
        """`POST /v1/sandboxes/{id}/fork`. Requires a persistent source workspace;
        returns HTTP 202 with the new child sandbox and its `ForkSandbox` operation."""
        request = CreateSandboxRequest(name=name, ttl_seconds=ttl_seconds)
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/fork",
            json_body=self._dump(request),
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SandboxResponse.model_validate(response.json())

    def wait_for_sandbox_ready(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 0.2,
        max_poll_interval: float = 3.0,
    ) -> Sandbox:
        """Polls `get_sandbox` with capped exponential backoff until `Ready`,
        mirroring the CLI's `new --wait`. Raises `SandboxwichError` if the
        sandbox reaches `Error`/`Archived`, or `TimeoutError` after `timeout`
        seconds."""
        deadline = time.monotonic() + timeout
        delay = poll_interval
        while True:
            sandbox = self.get_sandbox(sandbox_id).sandbox
            if sandbox.state == SandboxState.ready:
                return sandbox
            if sandbox.state == SandboxState.error:
                raise SandboxwichError(f"sandbox {sandbox_id} entered the error state")
            if sandbox.state == SandboxState.archived:
                raise SandboxwichError(f"sandbox {sandbox_id} was archived before it became ready")
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timed out after {timeout}s waiting for sandbox {sandbox_id} "
                    f"(last state: {sandbox.state})"
                )
            time.sleep(delay)
            delay = min(delay * 2, max_poll_interval)

    # ----------------------------------------------------------------
    # Commands
    # ----------------------------------------------------------------

    def run_command(
        self,
        sandbox_id: uuid.UUID | str,
        argv: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_secs: int | None = None,
        idempotency_key: str | None = None,
    ) -> QueueCommandResponse:
        """`POST /v1/sandboxes/{id}/commands`. Returns HTTP 202 with the queued
        `CommandRun` (status `Queued`) and its `Operation`. Use `wait_for_command`
        or `stream_command_output` to observe completion."""
        request = CommandRequest(argv=argv, cwd=cwd, env=env or {}, timeout_secs=timeout_secs)
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/commands",
            json_body=self._dump(request),
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return QueueCommandResponse.model_validate(response.json())

    def list_commands(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> CommandListResponse:
        response = self._request(
            "GET",
            f"/v1/sandboxes/{sandbox_id}/commands",
            params={"limit": limit, "after": after, "before": before},
        )
        return CommandListResponse.model_validate(response.json())

    def get_command(self, command_id: uuid.UUID | str) -> CommandResponse:
        response = self._request("GET", f"/v1/commands/{command_id}")
        return CommandResponse.model_validate(response.json())

    def list_command_output(
        self,
        command_id: uuid.UUID | str,
        *,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> CommandOutputListResponse:
        """`GET /v1/commands/{id}/output`. `chunks` are ordered by `sequence`;
        `complete=False` means the command may still append more."""
        response = self._request(
            "GET",
            f"/v1/commands/{command_id}/output",
            params={"limit": limit, "after": after, "before": before},
        )
        return CommandOutputListResponse.model_validate(response.json())

    def wait_for_command(
        self,
        command_id: uuid.UUID | str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 0.2,
        max_poll_interval: float = 5.0,
    ) -> CommandRun:
        """Polls `get_command` with capped exponential backoff until the command
        reaches `Finished`/`Failed`, mirroring the CLI's `exec --wait`."""
        deadline = time.monotonic() + timeout
        delay = poll_interval
        while True:
            command = self.get_command(command_id).command
            if command.status in _TERMINAL_COMMAND_STATES:
                return command
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timed out after {timeout}s waiting for command {command_id} "
                    f"(last status: {command.status})"
                )
            time.sleep(delay)
            delay = min(delay * 2, max_poll_interval)

    def stream_command_output(
        self,
        command_id: uuid.UUID | str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 0.2,
        max_poll_interval: float = 5.0,
    ) -> Iterator[CommandOutputChunk]:
        """Yields `CommandOutputChunk`s in `sequence` order as they become
        available, mirroring the CLI's `exec --follow`.

        Unlike the CLI (which re-fetches the whole output list every poll and
        tracks how many chunks it has already printed), this walks the
        `next_cursor` keyset cursor returned by `GET /commands/{id}/output`:
        each already-seen page is never re-fetched, so output is drained
        strictly once and in the order the server appended it. Stops once the
        command is terminal (`Finished`/`Failed`) and the output list reports
        `complete=True` with no further pages.
        """
        deadline = time.monotonic() + timeout
        delay = poll_interval
        cursor: str | None = None
        while True:
            output = self.list_command_output(command_id, after=cursor)
            for chunk in output.chunks:
                yield chunk
            if output.next_cursor:
                cursor = output.next_cursor
                delay = poll_interval
                continue  # more pages are immediately available; keep draining
            command = self.get_command(command_id).command
            if output.complete and command.status in _TERMINAL_COMMAND_STATES:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timed out after {timeout}s streaming output for command {command_id}"
                )
            time.sleep(delay)
            delay = min(delay * 2, max_poll_interval)

    # ----------------------------------------------------------------
    # Files
    # ----------------------------------------------------------------

    def upload_file(
        self,
        sandbox_id: uuid.UUID | str,
        local_path: str | Path,
        *,
        remote_path: str | None = None,
        mime_type: str | None = None,
    ) -> FileResponse:
        """`POST /v1/sandboxes/{id}/files` (multipart). Deliberately sends no
        Idempotency-Key: the API buffers idempotent bodies up to its normal
        1 MiB limit, which would turn a large upload into a 413."""
        local_path = Path(local_path)
        content = local_path.read_bytes()
        files = {"file": (local_path.name, content, mime_type or "application/octet-stream")}
        data = {"path": remote_path or local_path.name}
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/files",
            data=data,
            files=files,
        )
        return FileResponse.model_validate(response.json())

    def list_files(self, sandbox_id: uuid.UUID | str) -> ListFilesResponse:
        response = self._request("GET", f"/v1/sandboxes/{sandbox_id}/files")
        return ListFilesResponse.model_validate(response.json())

    def download_file(
        self,
        sandbox_id: uuid.UUID | str,
        remote_path: str,
        local_path: str | Path,
    ) -> Path:
        """Looks up `remote_path` via `list_files` (the API has no lookup-by-path
        route) then streams `GET /v1/sandboxes/{id}/files/{file_id}` to `local_path`.
        Returns the written path."""
        files = self.list_files(sandbox_id).files
        match = next((f for f in files if f.path == remote_path), None)
        if match is None:
            raise SandboxwichError(f"remote file {remote_path!r} was not found in sandbox {sandbox_id}")
        response = self._request(
            "GET", f"/v1/sandboxes/{sandbox_id}/files/{match.id}"
        )
        local_path = Path(local_path)
        local_path.write_bytes(response.content)
        return local_path

    # ----------------------------------------------------------------
    # Events
    # ----------------------------------------------------------------

    def list_events(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> EventListResponse:
        response = self._request(
            "GET",
            f"/v1/sandboxes/{sandbox_id}/events",
            params={"limit": limit, "after": after, "before": before},
        )
        return EventListResponse.model_validate(response.json())

    # ----------------------------------------------------------------
    # Snapshots
    # ----------------------------------------------------------------

    def create_snapshot(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        label: str | None = None,
        ttl_seconds: int | None = None,
        inventory: Any | None = None,
        provider_metadata: Any | None = None,
        idempotency_key: str | None = None,
    ) -> SnapshotResponse:
        """`POST /v1/sandboxes/{id}/snapshots`. Returns HTTP 202: the snapshot
        starts `Pending` and becomes `Ready` once its `CreateSnapshot` job completes.
        Requires a working CSI `VolumeSnapshotClass` in apply mode (see docs/capabilities.md)."""
        request = CreateSnapshotRequest(
            label=label,
            inventory=inventory,
            provider_metadata=provider_metadata,
            ttl_seconds=ttl_seconds,
        )
        response = self._request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/snapshots",
            json_body=self._dump(request),
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SnapshotResponse.model_validate(response.json())

    def list_snapshots(
        self,
        sandbox_id: uuid.UUID | str,
        *,
        limit: int | None = None,
        after: str | None = None,
        before: str | None = None,
    ) -> SnapshotListResponse:
        response = self._request(
            "GET",
            f"/v1/sandboxes/{sandbox_id}/snapshots",
            params={"limit": limit, "after": after, "before": before},
        )
        return SnapshotListResponse.model_validate(response.json())

    def get_snapshot(self, snapshot_id: uuid.UUID | str) -> SnapshotResponse:
        response = self._request("GET", f"/v1/snapshots/{snapshot_id}")
        return SnapshotResponse.model_validate(response.json())

    def restore_snapshot(
        self,
        snapshot_id: uuid.UUID | str,
        *,
        template: str,
        memory_limit: MemoryLimit,
        name: str | None = None,
        network_egress: NetworkEgress | None = None,
        ttl_seconds: int | None = None,
        idempotency_key: str | None = None,
    ) -> SandboxResponse:
        """`POST /v1/snapshots/{id}/fork`: restores directly from a durable
        snapshot into a brand-new sandbox, without depending on the source
        sandbox still existing. Returns HTTP 202 with the new sandbox and its
        `ForkSandbox` operation."""
        request = ForkSnapshotRequest(
            name=name,
            template=template,
            memory_limit=memory_limit,
            network_egress=network_egress or NetworkEgressDenyAll(),
            ttl_seconds=ttl_seconds,
        )
        response = self._request(
            "POST",
            f"/v1/snapshots/{snapshot_id}/fork",
            json_body=self._dump(request),
            mutating=True,
            idempotency_key=idempotency_key,
        )
        return SandboxResponse.model_validate(response.json())

    # ----------------------------------------------------------------
    # Health
    # ----------------------------------------------------------------

    def health(self) -> HealthResponse:
        """`GET /healthz`: liveness only, no auth or database check."""
        response = self._request("GET", "/healthz")
        return HealthResponse.model_validate(response.json())

    def ready(self) -> HealthResponse:
        """`GET /readyz`: liveness plus a database round-trip."""
        response = self._request("GET", "/readyz")
        return HealthResponse.model_validate(response.json())
