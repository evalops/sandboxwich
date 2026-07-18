"""Tests for error-code-to-exception mapping, per the API's stable
`{ "ok": false, "code", "message" }` envelope (README's "Public API contract")."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
import respx

from sandboxwich import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    RateLimitedError,
    SandboxwichConnectionError,
    SandboxwichError,
    SandboxwichTimeoutError,
    ServerError,
    SandboxwichClient,
    UnauthorizedError,
    UnsupportedError,
)

BASE_URL = "http://sandboxwich.test"


@pytest.fixture
def client():
    with SandboxwichClient(BASE_URL, api_token="test-token") as c:
        yield c


def _error_body(code: str, message: str) -> dict:
    return {"ok": False, "code": code, "message": message}


@respx.mock
def test_400_maps_to_bad_request_error(client):
    sandbox_id = uuid4()
    respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/commands").mock(
        return_value=httpx.Response(400, json=_error_body("bad_request", "argv must contain at least one item"))
    )

    with pytest.raises(BadRequestError) as excinfo:
        client.run_command(sandbox_id, [])

    assert excinfo.value.status_code == 400
    assert excinfo.value.code == "bad_request"
    assert "argv" in str(excinfo.value)


@respx.mock
def test_401_maps_to_unauthorized_error(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(401, json=_error_body("unauthorized", "valid bearer token is required"))
    )

    with pytest.raises(UnauthorizedError) as excinfo:
        client.list_sandboxes()

    assert excinfo.value.status_code == 401


@respx.mock
def test_404_maps_to_not_found_error(client):
    sandbox_id = uuid4()
    respx.get(f"{BASE_URL}/v1/sandboxes/{sandbox_id}").mock(
        return_value=httpx.Response(404, json=_error_body("not_found", "sandbox not found"))
    )

    with pytest.raises(NotFoundError):
        client.get_sandbox(sandbox_id)


@respx.mock
def test_409_maps_to_conflict_error(client):
    sandbox_id = uuid4()
    respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/stop").mock(
        return_value=httpx.Response(
            409, json=_error_body("conflict", "sandbox is not in a state stop can act on")
        )
    )

    with pytest.raises(ConflictError):
        client.stop_sandbox(sandbox_id)


@respx.mock
def test_429_maps_to_rate_limited_error_with_retry_after(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(
            429,
            json=_error_body("tenant_rate_limit_exceeded", "too many requests"),
            headers={"retry-after": "7"},
        )
    )

    with pytest.raises(RateLimitedError) as excinfo:
        client.list_sandboxes()

    assert excinfo.value.retry_after == 7
    assert excinfo.value.code == "tenant_rate_limit_exceeded"


@respx.mock
def test_501_resume_sandbox_maps_to_unsupported_error(client):
    sandbox_id = uuid4()
    respx.post(f"{BASE_URL}/v1/sandboxes/{sandbox_id}/resume").mock(
        return_value=httpx.Response(
            501,
            json=_error_body("unsupported", f"resume is not supported for sandbox {sandbox_id}"),
        )
    )

    with pytest.raises(UnsupportedError) as excinfo:
        client.resume_sandbox(sandbox_id)

    assert excinfo.value.status_code == 501
    assert excinfo.value.code == "unsupported"


@respx.mock
def test_500_maps_to_server_error(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(
        return_value=httpx.Response(500, json=_error_body("internal", "database operation failed"))
    )

    with pytest.raises(ServerError):
        client.list_sandboxes()


@respx.mock
def test_error_body_that_is_not_json_falls_back_to_raw_text(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(return_value=httpx.Response(502, text="bad gateway"))

    with pytest.raises(ServerError) as excinfo:
        client.list_sandboxes()

    assert excinfo.value.code is None
    assert "bad gateway" in str(excinfo.value)


@respx.mock
def test_connection_error_maps_to_sandboxwich_connection_error(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(side_effect=httpx.ConnectError("connection refused"))

    with pytest.raises(SandboxwichConnectionError):
        client.list_sandboxes()


@respx.mock
def test_timeout_maps_to_sandboxwich_timeout_error(client):
    respx.get(f"{BASE_URL}/v1/sandboxes").mock(side_effect=httpx.ReadTimeout("timed out"))

    with pytest.raises(SandboxwichTimeoutError):
        client.list_sandboxes()


def test_all_error_subclasses_are_sandboxwich_errors():
    for cls in (
        BadRequestError,
        UnauthorizedError,
        NotFoundError,
        ConflictError,
        UnsupportedError,
        RateLimitedError,
        ServerError,
        SandboxwichConnectionError,
        SandboxwichTimeoutError,
    ):
        assert issubclass(cls, SandboxwichError)
