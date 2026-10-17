"""Path parameters are encoded as one segment; empty, '.' and '..' are rejected."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
import respx

from shieldcortex import AsyncShieldCortex, ShieldCortex
from shieldcortex._http import _seg
from tests.test_audit_exports import EXPORT_VERIFY_RESPONSE

INVALID = ["", ".", ".."]

# One route per HTTP method, each taking the path parameter positionally.
SyncCall = Callable[[ShieldCortex, Any], Any]
AsyncCall = Callable[[AsyncShieldCortex, Any], Awaitable[Any]]

SYNC_ROUTES: list[tuple[str, SyncCall]] = [
    ("GET", lambda c, v: c.get_webhook_deliveries(v)),
    ("POST", lambda c, v: c.resend_invite(v)),
    ("PATCH", lambda c, v: c.update_device(v, "laptop")),
    ("DELETE", lambda c, v: c.revoke_api_key(v)),
]

ASYNC_ROUTES: list[tuple[str, AsyncCall]] = [
    ("GET", lambda c, v: c.get_webhook_deliveries(v)),
    ("POST", lambda c, v: c.resend_invite(v)),
    ("PATCH", lambda c, v: c.update_device(v, "laptop")),
    ("DELETE", lambda c, v: c.revoke_api_key(v)),
]

ROUTE_PATHS = {
    "GET": "/v1/webhooks/{}/deliveries",
    "POST": "/v1/invites/{}/resend",
    "PATCH": "/v1/devices/{}",
    "DELETE": "/v1/keys/{}",
}


def _ok() -> httpx.Response:
    return httpx.Response(200, json={"deliveries": []})


# ── Helper ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("abc-123", "abc-123"),
        (42, "42"),
        ("a/b?c#d", "a%2Fb%3Fc%23d"),
        ("50% off", "50%25%20off"),
        ("café", "caf%C3%A9"),
        ("a..b", "a..b"),
        (".hidden", ".hidden"),
    ],
)
def test_seg_encodes_one_segment(value: object, expected: str) -> None:
    assert _seg(value) == expected


def test_seg_rejects_empty() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        _seg("")


@pytest.mark.parametrize("value", [".", ".."])
def test_seg_rejects_dot_segments(value: str) -> None:
    with pytest.raises(ValueError, match="must not be '.' or '..'"):
        _seg(value)


# ── Encoding on the wire ──────────────────────────────────────────────────────


@pytest.mark.parametrize(("method", "call"), SYNC_ROUTES, ids=[m for m, _ in SYNC_ROUTES])
@respx.mock
def test_reserved_chars_stay_one_segment(
    client: ShieldCortex, method: str, call: SyncCall
) -> None:
    respx.route().mock(return_value=_ok())
    call(client, "a/b?c#d")

    request = respx.calls.last.request
    assert request.method == method
    assert request.url.raw_path == ROUTE_PATHS[method].format("a%2Fb%3Fc%23d").encode()
    assert request.url.query == b""


@pytest.mark.parametrize(("method", "call"), ASYNC_ROUTES, ids=[m for m, _ in ASYNC_ROUTES])
@respx.mock
async def test_async_reserved_chars_stay_one_segment(
    async_client: AsyncShieldCortex, method: str, call: AsyncCall
) -> None:
    respx.route().mock(return_value=_ok())
    await call(async_client, "a/b?c#d")

    request = respx.calls.last.request
    assert request.method == method
    assert request.url.raw_path == ROUTE_PATHS[method].format("a%2Fb%3Fc%23d").encode()
    assert request.url.query == b""


@respx.mock
def test_audit_export_id_is_encoded(client: ShieldCortex) -> None:
    respx.route().mock(return_value=httpx.Response(200, json=EXPORT_VERIFY_RESPONSE))
    client.verify_audit_export("exp 1/é")

    assert respx.calls.last.request.url.raw_path == (
        b"/v1/audit/exports/exp%201%2F%C3%A9/verify"
    )


@pytest.mark.parametrize("value", ["a..b", ".hidden"])
@respx.mock
def test_dot_containing_ids_are_accepted(client: ShieldCortex, value: str) -> None:
    respx.route().mock(return_value=_ok())
    client.update_device(value, "laptop")

    assert respx.calls.last.request.url.raw_path == f"/v1/devices/{value}".encode()


@pytest.mark.parametrize("value", ["a..b", ".hidden"])
@respx.mock
async def test_async_dot_containing_ids_are_accepted(
    async_client: AsyncShieldCortex, value: str
) -> None:
    respx.route().mock(return_value=_ok())
    await async_client.update_device(value, "laptop")

    assert respx.calls.last.request.url.raw_path == f"/v1/devices/{value}".encode()


# ── Rejection before any request ──────────────────────────────────────────────


@pytest.mark.parametrize("value", INVALID)
@pytest.mark.parametrize(("method", "call"), SYNC_ROUTES, ids=[m for m, _ in SYNC_ROUTES])
@respx.mock
def test_invalid_ids_raise_before_request(
    client: ShieldCortex, method: str, call: SyncCall, value: str
) -> None:
    route = respx.route().mock(return_value=_ok())
    with pytest.raises(ValueError, match="path parameter"):
        call(client, value)

    assert not route.called
    assert respx.calls.call_count == 0


@pytest.mark.parametrize("value", INVALID)
@pytest.mark.parametrize(("method", "call"), ASYNC_ROUTES, ids=[m for m, _ in ASYNC_ROUTES])
@respx.mock
async def test_async_invalid_ids_raise_before_request(
    async_client: AsyncShieldCortex, method: str, call: AsyncCall, value: str
) -> None:
    route = respx.route().mock(return_value=_ok())
    with pytest.raises(ValueError, match="path parameter"):
        await call(async_client, value)

    assert not route.called
    assert respx.calls.call_count == 0
