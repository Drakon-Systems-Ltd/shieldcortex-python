"""Cross-SDK endpoint parity guard.

Drift tripwire, NOT a correctness proof. It asserts every manifest path
template appears in the client source (so the manifest can't silently rot),
but it does not prove the method attached to each path (e.g. GET vs POST
/v1/sync/memories share one template), nor that the client has no endpoints
missing from the manifest. Review both files together whenever the API
surface changes.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from shieldcortex import AsyncShieldCortex, ShieldCortex
from tests.endpoint_manifest import COVERED, DEFERRED

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "shieldcortex"


def _camelise(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _normalised_source(filename: str) -> str:
    # Normalise Python f-string params (`{manifest_id}` → `{manifestId}`) so
    # the source can be matched against the manifest's placeholder form.
    source = (_SRC_DIR / filename).read_text()
    return re.sub(r"\{(\w+)\}", lambda m: "{" + _camelise(m.group(1)) + "}", source)


# The async twins duplicate every path literal, so both sources are guarded —
# a typo in either client trips the check.
_NORMALISED_SOURCES = {
    filename: _normalised_source(filename)
    for filename in ("client.py", "async_client.py")
}


def _appears_in_source(path: str, normalised: str) -> bool:
    # Anchored on the closing delimiter so a path that merely prefixes another
    # (e.g. /v1/audit inside /v1/audit/stats) cannot satisfy the check. The
    # char class mirrors the TS guard's delimiter set (quote/backtick/$/?);
    # only the quotes can ever end a Python literal, the rest are inert here.
    return re.search(re.escape(path) + r'["\'`$?]', normalised) is not None


def test_every_covered_path_appears_in_both_client_sources() -> None:
    missing = [
        (filename, method, path)
        for filename, normalised in _NORMALISED_SOURCES.items()
        for method, path in COVERED
        if not _appears_in_source(path, normalised)
    ]
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


def _public_callables(cls: type) -> set[str]:
    return {
        name
        for name in dir(cls)
        if not name.startswith("_") and callable(getattr(cls, name))
    }


def test_sync_and_async_clients_expose_identical_surfaces() -> None:
    """The two clients must never drift: identical public callable names."""
    assert _public_callables(ShieldCortex) == _public_callables(AsyncShieldCortex)


def test_sync_and_async_methods_have_identical_signatures() -> None:
    """Per shared public method, the full parameter list (names, kinds,
    defaults, annotations) must match — this closes kwarg drift for the
    pre-existing inline groups the shared builders don't cover. Return
    annotations are excluded (iterators/awaitables legitimately differ)."""
    drifted = []
    for name in sorted(_public_callables(ShieldCortex) & _public_callables(AsyncShieldCortex)):
        sync_sig = inspect.signature(getattr(ShieldCortex, name))
        async_sig = inspect.signature(getattr(AsyncShieldCortex, name))
        if sync_sig.parameters != async_sig.parameters:
            drifted.append((name, str(sync_sig), str(async_sig)))
    assert drifted == []
