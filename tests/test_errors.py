"""Tests for error hierarchy."""

from __future__ import annotations

from shieldcortex.errors import (
    AuthError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ShieldCortexError,
    ValidationError,
)


def test_error_hierarchy() -> None:
    assert issubclass(AuthError, ShieldCortexError)
    assert issubclass(RateLimitError, ShieldCortexError)
    assert issubclass(ValidationError, ShieldCortexError)
    assert issubclass(NotFoundError, ShieldCortexError)
    assert issubclass(ForbiddenError, ShieldCortexError)


def test_auth_error_fields() -> None:
    err = AuthError('{"error": "Invalid key"}')
    assert err.status_code == 401
    assert "Authentication" in str(err)
    assert err.body == '{"error": "Invalid key"}'


def test_rate_limit_error_retry_after() -> None:
    err = RateLimitError('{"error": "Rate limit"}', retry_after=60)
    assert err.status_code == 429
    assert err.retry_after == 60


def test_rate_limit_error_no_retry_after() -> None:
    err = RateLimitError('{"error": "Rate limit"}')
    assert err.retry_after is None


def test_base_error_fields() -> None:
    err = ShieldCortexError("Something failed", 503, "Service Unavailable")
    assert err.status_code == 503
    assert err.body == "Service Unavailable"
    assert str(err) == "Something failed"


def test_errors_are_exceptions() -> None:
    for cls in [AuthError, ValidationError, NotFoundError, ForbiddenError]:
        assert issubclass(cls, Exception)
