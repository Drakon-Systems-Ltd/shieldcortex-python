"""Auto-pagination iterators for ShieldCortex API responses."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING

from shieldcortex.types import AuditEntry, AuditQuery

if TYPE_CHECKING:
    from shieldcortex.async_client import AsyncShieldCortex
    from shieldcortex.client import ShieldCortex


class AuditPaginator:
    """Synchronous auto-pagination iterator for audit logs.

    Yields AuditEntry objects, automatically fetching the next page
    when the current one is exhausted.

    Example::

        for entry in AuditPaginator(client, AuditQuery(), page_size=100):
            print(entry.id, entry.firewall_result)
    """

    def __init__(
        self,
        client: ShieldCortex,
        query: AuditQuery,
        page_size: int = 100,
    ) -> None:
        self._client = client
        self._query = query
        self._page_size = page_size
        self._offset = query.offset

    def __iter__(self) -> Iterator[AuditEntry]:
        while True:
            page_query = AuditQuery(
                from_time=self._query.from_time,
                to=self._query.to,
                level=self._query.level,
                source=self._query.source,
                device_id=self._query.device_id,
                search=self._query.search,
                limit=self._page_size,
                offset=self._offset,
            )
            response = self._client.get_audit_logs(page_query)

            if not response.logs:
                break

            yield from response.logs

            if not response.pagination.has_more:
                break

            self._offset += self._page_size


class AsyncAuditPaginator:
    """Async auto-pagination iterator for audit logs.

    Example::

        async for entry in AsyncAuditPaginator(client, AuditQuery()):
            print(entry.id, entry.firewall_result)
    """

    def __init__(
        self,
        client: AsyncShieldCortex,
        query: AuditQuery,
        page_size: int = 100,
    ) -> None:
        self._client = client
        self._query = query
        self._page_size = page_size
        self._offset = query.offset

    async def __aiter__(self) -> AsyncIterator[AuditEntry]:
        while True:
            page_query = AuditQuery(
                from_time=self._query.from_time,
                to=self._query.to,
                level=self._query.level,
                source=self._query.source,
                device_id=self._query.device_id,
                search=self._query.search,
                limit=self._page_size,
                offset=self._offset,
            )
            response = await self._client.get_audit_logs(page_query)

            if not response.logs:
                break

            for entry in response.logs:
                yield entry

            if not response.pagination.has_more:
                break

            self._offset += self._page_size
