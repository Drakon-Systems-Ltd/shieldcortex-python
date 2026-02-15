"""Shared HTTP utilities for sync and async clients.

Handles serialisation, deserialisation, and error mapping between
the ShieldCortex API's mixed-case JSON and Python snake_case dataclasses.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, TypeVar, get_type_hints

import httpx

from shieldcortex._version import __version__
from shieldcortex.errors import (
    AuthError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ShieldCortexError,
    ValidationError,
)

T = TypeVar("T")

DEFAULT_BASE_URL = "https://api.shieldcortex.ai"
DEFAULT_TIMEOUT = 30.0

# ── Case conversion ───────────────────────────────────────────────────────────

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])([A-Z])")


def _to_snake(name: str) -> str:
    """Convert camelCase or PascalCase to snake_case."""
    return _CAMEL_RE.sub(r"_\1", name).lower()


def _to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# ── Field name mappings for API ↔ Python ──────────────────────────────────────

# Python field name → API query parameter name (for query params that differ)
_QUERY_ALIASES: dict[str, str] = {
    "from_time": "from",
}


# ── Serialisation ─────────────────────────────────────────────────────────────


def serialize(obj: Any) -> Any:
    """Convert a dataclass (or primitive) to an API-compatible dict.

    - Dataclass fields are converted to camelCase
    - None values are omitted
    - Nested dataclasses are recursed
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        result: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            value = getattr(obj, f.name)
            if value is None:
                continue
            api_key = _to_camel(f.name)
            result[api_key] = serialize(value)
        return result
    if isinstance(obj, list):
        return [serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {k: serialize(v) for k, v in obj.items()}
    return obj


def serialize_query(obj: Any) -> dict[str, str]:
    """Convert a dataclass to query parameter dict (string values, no Nones)."""
    if not dataclasses.is_dataclass(obj) or isinstance(obj, type):
        return {}
    params: dict[str, str] = {}
    for f in dataclasses.fields(obj):
        value = getattr(obj, f.name)
        if value is None:
            continue
        param_name = _QUERY_ALIASES.get(f.name, f.name)
        params[param_name] = str(value)
    return params


# ── Deserialisation ───────────────────────────────────────────────────────────

# Cache for resolved type hints per class
_HINTS_CACHE: dict[type, dict[str, Any]] = {}


def _get_hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS_CACHE:
        _HINTS_CACHE[cls] = get_type_hints(cls)
    return _HINTS_CACHE[cls]


def _normalise_keys(data: dict[str, Any]) -> dict[str, Any]:
    """Normalise all keys in a dict to snake_case."""
    return {_to_snake(k): v for k, v in data.items()}


def _unwrap_optional(hint: Any) -> Any:
    """Extract T from Optional[T] (i.e. Union[T, None] or T | None)."""
    import types as builtin_types
    import typing

    # Python 3.10+ union: X | None (types.UnionType)
    _union_type = getattr(builtin_types, "UnionType", None)
    if _union_type is not None and isinstance(hint, _union_type):
        args = hint.__args__
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return non_none[0]
        return hint

    # typing.Union / typing.Optional
    origin = getattr(hint, "__origin__", None)
    if origin is getattr(typing, "Union", None):
        args = getattr(hint, "__args__", ())
        if type(None) in args:
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1:
                return non_none[0]

    return hint


def _is_list_type(hint: Any) -> bool:
    origin = getattr(hint, "__origin__", None)
    return origin is list


def _get_list_item_type(hint: Any) -> Any:
    args = getattr(hint, "__args__", ())
    return args[0] if args else Any


def deserialize(data: Any, cls: type[T]) -> T:
    """Convert an API response dict to a typed dataclass.

    Handles:
    - camelCase → snake_case key normalisation
    - Nested dataclass construction
    - List[Dataclass] fields
    - Optional fields with defaults
    """
    if not dataclasses.is_dataclass(cls):
        return data  # type: ignore[no-any-return]

    if not isinstance(data, dict):
        return data  # type: ignore[no-any-return]

    normalised = _normalise_keys(data)
    hints = _get_hints(cls)
    fields = {f.name for f in dataclasses.fields(cls)}
    kwargs: dict[str, Any] = {}

    for fname in fields:
        if fname not in normalised:
            # Let the dataclass default handle it
            continue

        value = normalised[fname]
        hint = hints.get(fname, Any)

        # Unwrap Optional[T]
        inner_hint = _unwrap_optional(hint)

        if value is None:
            kwargs[fname] = None
        elif dataclasses.is_dataclass(inner_hint) and isinstance(value, dict):
            kwargs[fname] = deserialize(value, inner_hint)  # type: ignore[arg-type]
        elif _is_list_type(inner_hint) and isinstance(value, list):
            item_type = _get_list_item_type(inner_hint)
            if dataclasses.is_dataclass(item_type):
                kwargs[fname] = [deserialize(item, item_type) for item in value]  # type: ignore[arg-type]
            else:
                kwargs[fname] = value
        else:
            kwargs[fname] = value

    return cls(**kwargs)


# ── Error mapping ─────────────────────────────────────────────────────────────


def raise_for_status(response: httpx.Response) -> None:
    """Raise a typed exception for non-2xx responses."""
    if response.is_success:
        return

    body = response.text
    status = response.status_code

    if status == 401:
        raise AuthError(body)
    elif status == 403:
        raise ForbiddenError(body)
    elif status == 404:
        raise NotFoundError(body)
    elif status == 429:
        retry_after_header = response.headers.get("retry-after")
        retry_after: int | None = None
        if retry_after_header:
            try:
                retry_after = int(retry_after_header)
            except ValueError:
                pass
        raise RateLimitError(body, retry_after)
    elif status == 400:
        raise ValidationError(body)
    else:
        raise ShieldCortexError(f"API error: {status}", status, body)


# ── Headers ───────────────────────────────────────────────────────────────────


def build_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": f"shieldcortex-python/{__version__}",
    }
