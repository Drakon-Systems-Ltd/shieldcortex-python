"""Cross-SDK endpoint parity guard.

Drift tripwire, NOT a correctness proof. It asserts every manifest path
template appears in the client source (so the manifest can't silently rot),
but it does not prove the method attached to each path (e.g. GET vs POST
/v1/sync/memories share one template), and substring matching can alias
(``/v1/audit/export`` also matches inside ``/v1/audit/exports``). Review
both files together whenever the API surface changes.
"""

from __future__ import annotations

import re
from pathlib import Path

from shieldcortex import AsyncShieldCortex, ShieldCortex
from tests.endpoint_manifest import COVERED, DEFERRED

_CLIENT_SOURCE = (
    Path(__file__).resolve().parent.parent / "src" / "shieldcortex" / "client.py"
).read_text()


def _camelise(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# Normalise Python f-string params (`{manifest_id}` → `{manifestId}`) so the
# source can be matched against the manifest's placeholder form.
_NORMALISED = re.sub(r"\{(\w+)\}", lambda m: "{" + _camelise(m.group(1)) + "}", _CLIENT_SOURCE)


def test_every_covered_path_appears_in_client_source() -> None:
    missing = [(method, path) for method, path in COVERED if path not in _NORMALISED]
    assert missing == []


def test_covered_has_no_duplicate_entries() -> None:
    seen: set[tuple[str, str]] = set()
    dupes = []
    for entry in COVERED:
        if entry in seen:
            dupes.append(entry)
        seen.add(entry)
    assert dupes == []


def test_no_covered_entry_is_also_deferred() -> None:
    overlap = set(COVERED) & set(DEFERRED)
    assert overlap == set()


def test_sync_and_async_clients_expose_identical_surfaces() -> None:
    """The two clients must never drift: identical public callable names."""

    def public_callables(cls: type) -> set[str]:
        return {
            name
            for name in dir(cls)
            if not name.startswith("_") and callable(getattr(cls, name))
        }

    assert public_callables(ShieldCortex) == public_callables(AsyncShieldCortex)
