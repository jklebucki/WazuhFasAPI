"""Client lookup and administrator agent list endpoints."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.dependencies import get_app_settings, get_data_service
from app.core.config import Settings
from app.core.security import require_admin_key, require_client_key
from app.models.agent import AgentList, AgentLookup, DuplicateAgent
from app.services.bootstrap import compatibility
from app.services.wazuh_data import WazuhDataService, to_agent

router = APIRouter(prefix="/api/v1", tags=["agents"])
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?\.?$")


def normalize_hostname(value: str) -> str:
    if not (1 <= len(value) <= 63) or not HOST_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid hostname")
    normalized = value.rstrip(".").split(".", 1)[0]
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid hostname")
    return normalized


async def _target(service: WazuhDataService, settings: Settings) -> str:
    if settings.target_agent_version != "auto":
        return compatibility(settings.target_agent_version, settings.target_agent_version).target
    manager = await service.manager()
    raw = manager.value.get("version")
    if not isinstance(raw, str):
        raise HTTPException(status_code=503, detail="Service Unavailable")
    return compatibility(raw, "auto").target


def _stale_header(response: Response, stale: bool) -> None:
    response.headers["Cache-Control"] = "no-store"
    if stale:
        response.headers["Warning"] = '110 - "Response is stale"'


@router.get(
    "/agents/{hostname}",
    response_model=AgentLookup,
    dependencies=[Depends(require_client_key)],
    responses={400: {"description": "Invalid hostname"}, 409: {"model": AgentLookup}},
)
async def agent_lookup(
    hostname: str,
    response: Response,
    service: WazuhDataService = Depends(get_data_service),
    settings: Settings = Depends(get_app_settings),
) -> AgentLookup:
    query = normalize_hostname(hostname)
    cached = await service.lookup(query)
    exact = [
        item
        for item in cached.value
        if item.get("id") != "000"
        and isinstance(item.get("name"), str)
        and str(item["name"]).casefold() == query.casefold()
    ]
    target = await _target(service, settings)
    _stale_header(response, cached.stale)
    if len(exact) > 1:
        response.status_code = status.HTTP_409_CONFLICT
        logging.getLogger(__name__).warning("duplicate Wazuh agent names detected")
        agents = [to_agent(item, target) for item in exact]
        return AgentLookup(
            query_name=query,
            registered=True,
            duplicate_count=len(agents),
            agent=None,
            duplicates=[
                DuplicateAgent(
                    id=item.id,
                    name=item.name,
                    status=item.status,
                    groups=item.groups,
                    last_keep_alive=item.last_keep_alive,
                )
                for item in agents
            ],
            data_as_of=cached.data_as_of,
            stale=cached.stale,
        )
    agent = to_agent(exact[0], target) if exact else None
    return AgentLookup(
        query_name=query,
        registered=agent is not None,
        duplicate_count=len(exact),
        agent=agent,
        data_as_of=cached.data_as_of,
        stale=cached.stale,
    )


@router.get(
    "/agents",
    response_model=AgentList,
    dependencies=[Depends(require_admin_key)],
)
async def agents_list(
    response: Response,
    status_filter: str | None = Query(None, alias="status", max_length=32),
    group: str | None = Query(None, max_length=128),
    platform: str | None = Query(None, max_length=64),
    name: str | None = Query(None, max_length=128),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    service: WazuhDataService = Depends(get_data_service),
    settings: Settings = Depends(get_app_settings),
) -> AgentList:
    cached = await service.agents()
    target = await _target(service, settings)
    items = [to_agent(raw, target) for raw in cached.value if raw.get("id") != "000"]
    if status_filter:
        items = [
            item for item in items if (item.status or "").casefold() == status_filter.casefold()
        ]
    if group:
        items = [
            item for item in items if any(g.casefold() == group.casefold() for g in item.groups)
        ]
    if platform:
        items = [
            item
            for item in items
            if (item.operating_system.platform or "").casefold() == platform.casefold()
        ]
    if name:
        items = [item for item in items if name.casefold() in item.name.casefold()]
    total = len(items)
    _stale_header(response, cached.stale)
    return AgentList(
        items=items[offset : offset + limit],
        total=total,
        limit=limit,
        offset=offset,
        data_as_of=cached.data_as_of,
        stale=cached.stale,
    )
