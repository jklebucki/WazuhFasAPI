"""Small asynchronous stale-while-error cache."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypeVar

from app.models.common import utc_now

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CacheValue[T]:
    value: T
    data_as_of: datetime
    stale: bool = False


@dataclass(slots=True)
class _Entry[T]:
    value: T
    stored_at: datetime


class AsyncTTLCache[T]:
    """Cache values and coalesce concurrent refreshes per key."""

    def __init__(self) -> None:
        self._entries: dict[str, _Entry[T]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._map_lock = asyncio.Lock()

    async def _lock_for(self, key: str) -> asyncio.Lock:
        async with self._map_lock:
            return self._locks.setdefault(key, asyncio.Lock())

    async def get_or_load(
        self,
        key: str,
        loader: Callable[[], Awaitable[T]],
        ttl_seconds: int,
        stale_seconds: int,
        stale_on: tuple[type[Exception], ...],
        *,
        allow_stale: bool = True,
    ) -> CacheValue[T]:
        now = utc_now()
        entry = self._entries.get(key)
        if entry and now - entry.stored_at <= timedelta(seconds=ttl_seconds):
            return CacheValue(entry.value, entry.stored_at)
        lock = await self._lock_for(key)
        async with lock:
            now = utc_now()
            entry = self._entries.get(key)
            if entry and now - entry.stored_at <= timedelta(seconds=ttl_seconds):
                return CacheValue(entry.value, entry.stored_at)
            try:
                value = await loader()
            except stale_on:
                if (
                    allow_stale
                    and entry
                    and now - entry.stored_at <= timedelta(seconds=ttl_seconds + stale_seconds)
                ):
                    logging.getLogger(__name__).warning(
                        "using stale Wazuh cache after upstream failure"
                    )
                    return CacheValue(entry.value, entry.stored_at, stale=True)
                raise
            stored_at = utc_now()
            self._entries[key] = _Entry(value, stored_at)
            return CacheValue(value, stored_at)

    def clear(self) -> None:
        self._entries.clear()
