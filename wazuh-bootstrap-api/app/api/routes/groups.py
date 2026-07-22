"""Administrator group endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Response

from app.api.dependencies import get_app_settings, get_data_service
from app.core.config import Settings
from app.core.security import require_admin_key
from app.models.group import GroupDetail, GroupList
from app.services.bootstrap import compatibility
from app.services.wazuh_data import WazuhDataService, to_agent, to_group

router = APIRouter(prefix="/api/v1/groups", tags=["groups"])


async def _target(service: WazuhDataService, settings: Settings) -> str:
    if settings.target_agent_version != "auto":
        return compatibility(settings.target_agent_version, settings.target_agent_version).target
    manager = await service.manager()
    raw = manager.value.get("version")
    if not isinstance(raw, str):
        raise HTTPException(status_code=503, detail="Service Unavailable")
    return compatibility(raw, "auto").target


@router.get("", response_model=GroupList, dependencies=[Depends(require_admin_key)])
async def groups_list(
    response: Response,
    service: WazuhDataService = Depends(get_data_service),
) -> GroupList:
    cached = await service.groups()
    items = [group for raw in cached.value if (group := to_group(raw)).name]
    response.headers["Cache-Control"] = "no-store"
    if cached.stale:
        response.headers["Warning"] = '110 - "Response is stale"'
    return GroupList(
        items=items, total=len(items), data_as_of=cached.data_as_of, stale=cached.stale
    )


@router.get("/{group_name}", response_model=GroupDetail, dependencies=[Depends(require_admin_key)])
async def group_detail(
    group_name: str,
    response: Response,
    service: WazuhDataService = Depends(get_data_service),
    settings: Settings = Depends(get_app_settings),
) -> GroupDetail:
    if not group_name or len(group_name) > 128:
        raise HTTPException(status_code=400, detail="Invalid group name")
    groups = await service.groups()
    matches = [
        to_group(raw)
        for raw in groups.value
        if to_group(raw).name.casefold() == group_name.casefold()
    ]
    if not matches:
        raise HTTPException(status_code=404, detail="Group not found")
    agents = await service.agents()
    target = await _target(service, settings)
    members = [
        to_agent(raw, target)
        for raw in agents.value
        if raw.get("id") != "000"
        and any(
            value.casefold() == matches[0].name.casefold() for value in to_agent(raw, target).groups
        )
    ]
    stale = groups.stale or agents.stale
    response.headers["Cache-Control"] = "no-store"
    if stale:
        response.headers["Warning"] = '110 - "Response is stale"'
    return GroupDetail(
        group=matches[0],
        agents=members,
        total=len(members),
        data_as_of=min(groups.data_as_of, agents.data_as_of),
        stale=stale,
    )
