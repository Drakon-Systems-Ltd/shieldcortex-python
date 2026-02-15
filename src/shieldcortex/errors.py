"""ShieldCortex exception hierarchy.

Maps HTTP status codes from the ShieldCortex API to typed exceptions.
"""

from __future__ import annotations


class ShieldCortexError(Exception):
    """Base exception for all ShieldCortex API errors."""

    def __init__(self, message: str, status_code: int, body: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AuthError(ShieldCortexError):
    """401 — Invalid or missing API key."""

    def __init__(self, body: str) -> None:
        super().__init__("Authentication failed — check your API key", 401, body)


class RateLimitError(ShieldCortexError):
    """429 — Rate limit exceeded."""

    def __init__(self, body: str, retry_after: int | None = None) -> None:
        super().__init__("Rate limit exceeded", 429, body)
        self.retry_after = retry_after


class ValidationError(ShieldCortexError):
    """400 — Invalid request parameters."""

    def __init__(self, body: str) -> None:
        super().__init__("Validation error", 400, body)


class NotFoundError(ShieldCortexError):
    """404 — Resource not found."""

    def __init__(self, body: str) -> None:
        super().__init__("Resource not found", 404, body)


class ForbiddenError(ShieldCortexError):
    """403 — Insufficient permissions or plan restriction."""

    def __init__(self, body: str) -> None:
        super().__init__("Forbidden — insufficient permissions", 403, body)
