"""Tests for `SandboxwichClient` request serialization and response parsing.

Uses `respx` to mock the `httpx` transport layer -- no network or live API
required. Each test targets one of the flows called out in the SDK task:
sandbox lifecycle, command run + poll/stream (respecting `sequence`), file
copy up/down, events, and snapshots.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
import respx

from sandboxwich import (
    CommandStatus,
    SandboxState,
    SandboxwichClient,
)

BASE_URL = "http://sandboxwich.test"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sandbox(sandbox_id, *, state="ready", name="demo"):
    return {
        "id": str(sandbox_id),
        "tenant_id": "default",
        "name": name,
        "state": state,
        "template": "ubuntu-dev",
        "memory_limit": "1g",
        "network_egress": {"mode": "deny_all"},
        "workspace_mode": "persistent",
        "created_at": _now(),
        "updated_at": _now(),
        "ttl_seconds": 3600,
        "parent_snapshot_id": None,
    }


def _operation(kind="provision_sandbox", resource_id=None):
    return {
        "id": str(uuid4()),
        "kind": kind,
        "status": "queued",
        "resource_id": str(resource_id) if resource_id else None,
        "created_at": _now(),
        "updated_at": _now(),
        "error_code": None,
        "error_message": None,
    }


@pytest.fixture
def client():
    with SandboxwichClient(BASE_URL, api_token="test-token") as c:
        yield c


# --------------------------------------------------------------------------
# Sandboxes
# --------------------------------------------------------------------------


@respx.mock
def test_create_sandbox_sends_bearer_auth_and_idempotency_key(client):
    sandbox_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(
            202,
            json={"ok": True, "sandbox": _sandbox(sandbox_id, state="planning"), "operation": _operation()},
        )
    )

    response = client.create_sandbox(name="demo", ttl_seconds=120)

    assert route.called
    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer test-token"
    assert "idempotency-key" in {k.lower() for k in request.headers.keys()}
    body = json.loads(request.content)
    assert body == {"name": "demo", "ttl_seconds": 120}

    assert response.ok is True
    assert response.sandbox.id == sandbox_id
    assert response.sandbox.state == SandboxState.planning
    assert response.operation is not None


@respx.mock
def test_create_sandbox_serializes_network_egress_allowlist(client):
    from sandboxwich import NetworkAllowRule, NetworkEgressAllowlist

    sandbox_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(
            202,
            json={"ok": True, "sandbox": _sandbox(sandbox_id), "operation": _operation()},
        )
    )

    client.create_sandbox(
        network_egress=NetworkEgressAllowlist(rules=[NetworkAllowRule(kind="cidr", value="10.0.0.0/8")])
    )

    body = json.loads(route.calls[0].request.content)
    assert body["network_egress"] == {
        "mode": "allowlist",
        "rules": [{"kind": "cidr", "value": "10.0.0.0/8"}],
    }


@respx.mock
def test_wait_for_sandbox_ready_polls_until_ready(client):
    sandbox_id = uuid4()
    responses = [
        httpx.Response(200, json={"ok": True, "sandbox": _sandbox(sandbox_id, state="provisioning")}),
        httpx.Response(200, json={"ok": True, "sandbox": _sandbox(sandbox_id, state="ready")}),
    ]
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}").mock(side_effect=responses)

    sandbox = client.wait_for_sandbox_ready(sandbox_id, timeout=5.0, poll_interval=0.01)

    assert sandbox.state == SandboxState.ready


@respx.mock
def test_wait_for_sandbox_ready_raises_on_error_state(client):
    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}").mock(
        return_value=httpx.Response(200, json={"ok": True, "sandbox": _sandbox(sandbox_id, state="error")})
    )

    from sandboxwich import SandboxwichError

    with pytest.raises(SandboxwichError, match="error state"):
        client.wait_for_sandbox_ready(sandbox_id, timeout=5.0, poll_interval=0.01)


@respx.mock
def test_wait_for_sandbox_ready_times_out(client):
    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}").mock(
        return_value=httpx.Response(200, json={"ok": True, "sandbox": _sandbox(sandbox_id, state="provisioning")})
    )

    with pytest.raises(TimeoutError):
        client.wait_for_sandbox_ready(sandbox_id, timeout=0.05, poll_interval=0.02)


@respx.mock
def test_list_sandboxes_forwards_pagination_params(client):
    route = respx.get(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(200, json={"ok": True, "sandboxes": [], "next_cursor": None})
    )

    client.list_sandboxes(limit=50, after="cursor-1")

    request = route.calls[0].request
    assert request.url.params["limit"] == "50"
    assert request.url.params["after"] == "cursor-1"
    assert "before" not in request.url.params


@respx.mock
def test_stop_sandbox(client):
    sandbox_id = uuid4()
    respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/stop").mock(
        return_value=httpx.Response(
            202,
            json={"ok": True, "sandbox": _sandbox(sandbox_id, state="archiving"), "operation": _operation("stop_sandbox")},
        )
    )

    response = client.stop_sandbox(sandbox_id)
    assert response.sandbox.state == SandboxState.archiving


@respx.mock
def test_fork_sandbox(client):
    sandbox_id = uuid4()
    child_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/fork").mock(
        return_value=httpx.Response(
            202,
            json={
                "ok": True,
                "sandbox": _sandbox(child_id, state="planning", name="demo-fork"),
                "operation": _operation("fork_sandbox", child_id),
            },
        )
    )

    response = client.fork_sandbox(sandbox_id, name="demo-fork")

    body = json.loads(route.calls[0].request.content)
    assert body == {"name": "demo-fork"}
    assert response.sandbox.id == child_id
    assert response.operation.kind.value == "fork_sandbox"


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _command(command_id, sandbox_id, *, status="queued", stdout="", stderr="", exit_code=None):
    return {
        "id": str(command_id),
        "sandbox_id": str(sandbox_id),
        "status": status,
        "argv": ["echo", "hi"],
        "cwd": None,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "created_at": _now(),
        "finished_at": _now() if status in ("finished", "failed") else None,
    }


@respx.mock
def test_run_command_serializes_argv_env_and_timeout(client):
    sandbox_id = uuid4()
    command_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/commands").mock(
        return_value=httpx.Response(
            202,
            json={
                "ok": True,
                "command": _command(command_id, sandbox_id),
                "queued_job": {
                    "id": str(uuid4()),
                    "sandbox_id": str(sandbox_id),
                    "command_id": str(command_id),
                    "kind": "run_command",
                    "status": "queued",
                    "required_capability": "run_command",
                },
                "operation": _operation("run_command", command_id),
            },
        )
    )

    response = client.run_command(sandbox_id, ["echo", "hi"], env={"FOO": "bar"}, timeout_secs=30)

    body = json.loads(route.calls[0].request.content)
    assert body == {"argv": ["echo", "hi"], "env": {"FOO": "bar"}, "timeout_secs": 30}
    assert response.command.id == command_id
    assert response.command.status == CommandStatus.queued


@respx.mock
def test_wait_for_command_polls_until_terminal(client):
    sandbox_id = uuid4()
    command_id = uuid4()
    responses = [
        httpx.Response(200, json={"ok": True, "command": _command(command_id, sandbox_id, status="running")}),
        httpx.Response(
            200,
            json={
                "ok": True,
                "command": _command(command_id, sandbox_id, status="finished", stdout="hi\n", exit_code=0),
            },
        ),
    ]
    respx.get(f"{BASE_URL}/v1/commands/{command_id}").mock(side_effect=responses)

    command = client.wait_for_command(command_id, timeout=5.0, poll_interval=0.01)

    assert command.status == CommandStatus.finished
    assert command.stdout == "hi\n"
    assert command.exit_code == 0


def _output_chunk(command_id, sequence, chunk, *, stream="stdout"):
    return {
        "id": str(uuid4()),
        "command_id": str(command_id),
        "stream": stream,
        "sequence": sequence,
        "chunk": chunk,
        "annotations": [],
        "created_at": _now(),
    }


@respx.mock
def test_stream_command_output_yields_chunks_in_sequence_order_across_pages(client):
    sandbox_id = uuid4()
    command_id = uuid4()

    # First page: two chunks, more available (next_cursor set).
    page_one = httpx.Response(
        200,
        json={
            "ok": True,
            "complete": False,
            "chunks": [
                _output_chunk(command_id, 0, "line 1\n"),
                _output_chunk(command_id, 1, "line 2\n"),
            ],
            "next_cursor": "cursor-a",
        },
    )
    # Second page (fetched with after=cursor-a): final chunk, no more pages, complete.
    page_two = httpx.Response(
        200,
        json={
            "ok": True,
            "complete": True,
            "chunks": [_output_chunk(command_id, 2, "line 3\n")],
            "next_cursor": None,
        },
    )
    respx.get(f"{BASE_URL}/v1/commands/{command_id}/output").mock(side_effect=[page_one, page_two])
    respx.get(f"{BASE_URL}/v1/commands/{command_id}").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "command": _command(command_id, sandbox_id, status="finished", exit_code=0)}
        )
    )

    chunks = list(client.stream_command_output(command_id, timeout=5.0, poll_interval=0.01))

    assert [c.sequence for c in chunks] == [0, 1, 2]
    assert [c.chunk for c in chunks] == ["line 1\n", "line 2\n", "line 3\n"]

    # The second output call must have used the cursor from the first page.
    output_calls = respx.get(f"{BASE_URL}/v1/commands/{command_id}/output").calls
    assert output_calls[1].request.url.params["after"] == "cursor-a"


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------


def _file(file_id, sandbox_id, path, *, size_bytes=5):
    return {
        "id": str(file_id),
        "sandbox_id": str(sandbox_id),
        "path": path,
        "size_bytes": size_bytes,
        "mime_type": "text/plain",
        "created_at": _now(),
        "updated_at": _now(),
    }


@respx.mock
def test_upload_file_sends_multipart_with_path_field(client, tmp_path):
    sandbox_id = uuid4()
    file_id = uuid4()
    local = tmp_path / "hello.txt"
    local.write_text("hello")

    route = respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/files").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "file": _file(file_id, sandbox_id, "workspace/hello.txt")}
        )
    )

    response = client.upload_file(sandbox_id, local, remote_path="workspace/hello.txt")

    request = route.calls[0].request
    assert b'name="path"' in request.content
    assert b"workspace/hello.txt" in request.content
    assert b'name="file"' in request.content
    assert response.file.path == "workspace/hello.txt"


@respx.mock
def test_download_file_looks_up_file_id_by_path_then_downloads(client, tmp_path):
    sandbox_id = uuid4()
    file_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/files").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "files": [
                    _file(uuid4(), sandbox_id, "other.txt"),
                    _file(file_id, sandbox_id, "workspace/hello.txt"),
                ],
            },
        )
    )
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/files/{file_id}").mock(
        return_value=httpx.Response(200, content=b"hello", headers={"content-type": "text/plain"})
    )

    destination = tmp_path / "downloaded.txt"
    result = client.download_file(sandbox_id, "workspace/hello.txt", destination)

    assert result == destination
    assert destination.read_bytes() == b"hello"


@respx.mock
def test_download_file_raises_not_found_error_for_unknown_path(client, tmp_path):
    from sandboxwich import SandboxwichError

    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/files").mock(
        return_value=httpx.Response(200, json={"ok": True, "files": []})
    )

    with pytest.raises(SandboxwichError, match="was not found"):
        client.download_file(sandbox_id, "missing.txt", tmp_path / "out.txt")


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


@respx.mock
def test_list_events(client):
    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/events").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "events": [
                    {
                        "id": str(uuid4()),
                        "sandbox_id": str(sandbox_id),
                        "kind": "lifecycle_changed",
                        "data": {"state": "ready"},
                        "created_at": _now(),
                    }
                ],
                "next_cursor": None,
            },
        )
    )

    response = client.list_events(sandbox_id)

    assert response.ok is True
    assert len(response.events) == 1
    assert response.events[0].kind.value == "lifecycle_changed"
    assert response.events[0].data == {"state": "ready"}


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


def _snapshot(snapshot_id, sandbox_id, *, status="pending"):
    return {
        "id": str(snapshot_id),
        "sandbox_id": str(sandbox_id),
        "status": status,
        "label": "test",
        "inventory": {},
        "provider_metadata": {},
        "created_at": _now(),
        "ready_at": None,
        "expires_at": None,
        "error": None,
    }


@respx.mock
def test_create_snapshot(client):
    sandbox_id = uuid4()
    snapshot_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/snapshots").mock(
        return_value=httpx.Response(
            202,
            json={
                "ok": True,
                "snapshot": _snapshot(snapshot_id, sandbox_id),
                "operation": _operation("create_snapshot", snapshot_id),
            },
        )
    )

    response = client.create_snapshot(sandbox_id, label="before-risky-change")

    body = json.loads(route.calls[0].request.content)
    assert body == {"label": "before-risky-change"}
    assert response.snapshot.id == snapshot_id


@respx.mock
def test_restore_snapshot_requires_template_and_memory_limit(client):
    from sandboxwich import MemoryLimit

    snapshot_id = uuid4()
    child_id = uuid4()
    route = respx.post(f"{BASE_URL}/v1/snapshots/{snapshot_id}/fork").mock(
        return_value=httpx.Response(
            202,
            json={
                "ok": True,
                "sandbox": _sandbox(child_id, state="planning"),
                "operation": _operation("fork_sandbox", child_id),
            },
        )
    )

    client.restore_snapshot(snapshot_id, template="ubuntu-dev", memory_limit=MemoryLimit.four_g)

    body = json.loads(route.calls[0].request.content)
    assert body["template"] == "ubuntu-dev"
    assert body["memory_limit"] == "4g"
    assert body["network_egress"] == {"mode": "deny_all"}


@respx.mock
def test_list_snapshots_for_sandbox(client):
    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/snapshots").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "snapshots": [_snapshot(uuid4(), sandbox_id)], "next_cursor": None}
        )
    )

    response = client.list_snapshots(sandbox_id)
    assert len(response.snapshots) == 1


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------


@respx.mock
def test_health(client):
    respx.get(f"{BASE_URL}/healthz").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "service": "sandboxwich-api", "checked_at": _now(), "database": None}
        )
    )

    response = client.health()
    assert response.ok is True
    assert response.service == "sandboxwich-api"
