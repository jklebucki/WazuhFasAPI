"""Validated adapters and cached read services for Wazuh data."""

from __future__ import annotations

from datetime import UTC, datetime

from app.clients.wazuh import JsonObject, JsonValue, WazuhClient, WazuhUnavailableError
from app.core.cache import AsyncTTLCache, CacheValue
from app.core.config import Settings
from app.models.agent import Agent, OperatingSystem
from app.models.group import Group
from app.services.bootstrap import compatibility, normalize_version, version_state


def _text(value: JsonValue | None) -> str | None:
    return str(value) if isinstance(value, str | int | float) else None


def _integer(value: JsonValue | None) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _date(value: JsonValue | None) -> datetime | None:
    if not isinstance(value, str) or not value or value == "n/a":
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _groups(value: JsonValue | None) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def to_agent(raw: JsonObject, target: str) -> Agent:
    os_data = raw.get("os")
    os_obj = os_data if isinstance(os_data, dict) else {}
    raw_version = _text(raw.get("version"))
    try:
        clean_version = normalize_version(raw_version) if raw_version else None
    except ValueError:
        clean_version = None
    return Agent(
        id=_text(raw.get("id")) or "",
        name=_text(raw.get("name")) or "",
        groups=_groups(raw.get("group")),
        status=_text(raw.get("status")),
        status_code=_integer(raw.get("status_code")),
        version_raw=raw_version,
        version=clean_version,
        version_state=version_state(raw_version, target),
        last_known_ip=_text(raw.get("ip")),
        registration_ip=_text(raw.get("registerIP")),
        last_keep_alive=_date(raw.get("lastKeepAlive")),
        date_added=_date(raw.get("dateAdd")),
        manager=_text(raw.get("manager")),
        node_name=_text(raw.get("node_name")),
        operating_system=OperatingSystem(
            platform=_text(os_obj.get("platform")),
            name=_text(os_obj.get("name")),
            version=_text(os_obj.get("version")),
        ),
    )


def to_group(raw: JsonObject) -> Group:
    name = _text(raw.get("name")) or _text(raw.get("group")) or ""
    count = None
    for field in ("count", "agent_count", "agents"):
        count = _integer(raw.get(field))
        if count is not None:
            break
    return Group(name=name, agent_count=count)


class WazuhDataService:
    def __init__(self, client: WazuhClient, settings: Settings) -> None:
        self.client = client
        self.settings = settings
        self.manager_cache: AsyncTTLCache[JsonObject] = AsyncTTLCache()
        self.agent_cache: AsyncTTLCache[list[JsonObject]] = AsyncTTLCache()
        self.agents_cache: AsyncTTLCache[list[JsonObject]] = AsyncTTLCache()
        self.groups_cache: AsyncTTLCache[list[JsonObject]] = AsyncTTLCache()
        self.readiness_cache: AsyncTTLCache[JsonObject] = AsyncTTLCache()

    async def manager(
        self, *, allow_stale: bool = True, ttl: int | None = None
    ) -> CacheValue[JsonObject]:
        return await self.manager_cache.get_or_load(
            "manager",
            self.client.manager_info,
            ttl if ttl is not None else self.settings.manager_cache_ttl_seconds,
            self.settings.upstream_stale_cache_seconds,
            (WazuhUnavailableError,),
            allow_stale=allow_stale,
        )

    async def lookup(self, hostname: str) -> CacheValue[list[JsonObject]]:
        return await self.agent_cache.get_or_load(
            hostname.casefold(),
            lambda: self.client.agents_by_name(hostname),
            self.settings.agents_cache_ttl_seconds,
            self.settings.upstream_stale_cache_seconds,
            (WazuhUnavailableError,),
        )

    async def agents(self) -> CacheValue[list[JsonObject]]:
        return await self.agents_cache.get_or_load(
            "all",
            self.client.all_agents,
            self.settings.agents_cache_ttl_seconds,
            self.settings.upstream_stale_cache_seconds,
            (WazuhUnavailableError,),
        )

    async def groups(self) -> CacheValue[list[JsonObject]]:
        return await self.groups_cache.get_or_load(
            "all",
            self.client.all_groups,
            self.settings.groups_cache_ttl_seconds,
            self.settings.upstream_stale_cache_seconds,
            (WazuhUnavailableError,),
        )

    async def readiness(self) -> CacheValue[JsonObject]:
        return await self.readiness_cache.get_or_load(
            "rbac",
            self.client.readiness_info,
            10,
            0,
            (WazuhUnavailableError,),
            allow_stale=False,
        )

    async def target_version(self, manager_raw: str) -> str:
        return compatibility(manager_raw, self.settings.target_agent_version).target
