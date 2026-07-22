from __future__ import annotations

import asyncio

import pytest

from app.core.cache import AsyncTTLCache


class TemporaryError(RuntimeError):
    pass


@pytest.mark.asyncio
async def test_cache_fresh_coalesced_and_clear() -> None:
    cache: AsyncTTLCache[int] = AsyncTTLCache()
    calls = 0

    async def load() -> int:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return 42

    first, second = await asyncio.gather(
        cache.get_or_load("x", load, 60, 60, (TemporaryError,)),
        cache.get_or_load("x", load, 60, 60, (TemporaryError,)),
    )
    assert first.value == second.value == 42
    assert calls == 1
    cache.clear()
    await cache.get_or_load("x", load, 60, 60, (TemporaryError,))
    assert calls == 2


@pytest.mark.asyncio
async def test_stale_on_allowed_error() -> None:
    cache: AsyncTTLCache[int] = AsyncTTLCache()

    async def good() -> int:
        return 7

    async def bad() -> int:
        raise TemporaryError

    await cache.get_or_load("x", good, 0, 100, (TemporaryError,))
    await asyncio.sleep(0.01)
    stale = await cache.get_or_load("x", bad, 0, 100, (TemporaryError,))
    assert stale.stale and stale.value == 7
    with pytest.raises(TemporaryError):
        await cache.get_or_load("x", bad, 0, 100, (TemporaryError,), allow_stale=False)
