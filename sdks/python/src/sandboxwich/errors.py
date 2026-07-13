"""Typed errors raised by `SandboxwichClient`.

Every non-2xx response from the API uses the stable
`{ "ok": false, "code": "...", "message": "..." }` envelope documented in
README.md's "Public API contract" section. Callers should branch on
`.code` (a stable machine-readable string), never on `.message` (free text).
"""

from __future__ import annotations

from .models import ErrorEnvelope


class SandboxwichError(Exception):
    """Base class for every error this client raises.

    `status_code` and `code` are always present for HTTP-level failures
    (`status_code` is `None` only for transport failures like a connection
    refusal or a request timeout -- see `SandboxwichConnectionError` and
    `SandboxwichTimeoutError`).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
        body: ErrorEnvelope | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"{type(self).__name__}(status_code={self.status_code!r}, "
            f"code={self.code!r}, message={str(self)!r})"
        )


class BadRequestError(SandboxwichError):
    """HTTP 400: malformed request (e.g. invalid network egress rule, empty argv)."""


class UnauthorizedError(SandboxwichError):
    """HTTP 401: missing or invalid bearer token."""


class NotFoundError(SandboxwichError):
    """HTTP 404: the resource (sandbox, command, snapshot, ...) does not exist for this tenant."""


class ConflictError(SandboxwichError):
    """HTTP 409: e.g. a double-stop, or forking a non-persistent workspace."""


class UnsupportedError(SandboxwichError):
    """HTTP 501: capability not implemented (e.g. `resume_sandbox` today; see docs/capabilities.md)."""


class RateLimitedError(SandboxwichError):
    """HTTP 429: tenant request/mutation quota exceeded.

    `retry_after` is the integer seconds from the response's `Retry-After`
    header, when present.
    """

    def __init__(self, *args: object, retry_after: int | None = None, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.retry_after = retry_after


class ServerError(SandboxwichError):
    """HTTP 5xx other than 501 (internal error)."""


class SandboxwichConnectionError(SandboxwichError):
    """The request never reached the server (DNS, refused connection, TLS, ...)."""


class SandboxwichTimeoutError(SandboxwichError):
    """The request exceeded the client's configured timeout."""


# HTTP status code -> exception class for statuses with a single obvious mapping.
# 429 is handled separately (needs Retry-After); anything unmapped falls back to
# SandboxwichError.
_STATUS_TO_ERROR: dict[int, type[SandboxwichError]] = {
    400: BadRequestError,
    401: UnauthorizedError,
    403: UnauthorizedError,
    404: NotFoundError,
    409: ConflictError,
    501: UnsupportedError,
}


def error_for_response(
    status_code: int,
    *,
    code: str | None,
    message: str,
    request_id: str | None,
    body: ErrorEnvelope | None,
    retry_after: int | None = None,
) -> SandboxwichError:
    """Maps an API error response to the most specific `SandboxwichError` subclass."""
    if status_code == 429:
        return RateLimitedError(
            message,
            status_code=status_code,
            code=code,
            request_id=request_id,
            body=body,
            retry_after=retry_after,
        )
    error_cls = _STATUS_TO_ERROR.get(status_code)
    if error_cls is None:
        error_cls = ServerError if status_code >= 500 else SandboxwichError
    return error_cls(
        message,
        status_code=status_code,
        code=code,
        request_id=request_id,
        body=body,
    )
