"""Unauthenticated, information-minimal health endpoints."""

import logging
from collections.abc import Mapping

from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import get_app_settings, get_data_service
from app.clients.wazuh import WazuhApiError
from app.core.config import Settings
from app.models.common import utc_now
from app.models.health import LiveHealth, ReadyHealth
from app.services.bootstrap import compatibility
from app.services.wazuh_data import WazuhDataService

router = APIRouter(prefix="/health", tags=["health"])


def manager_version(raw: Mapping[str, object]) -> str:
    value = raw.get("version")
    if not isinstance(value, str):
        raise ValueError("manager version is missing")
    return value


@router.get("/live", response_model=LiveHealth)
async def live(settings: Settings = Depends(get_app_settings)) -> LiveHealth:
    return LiveHealth(service=settings.app_name, version=settings.app_version, time=utc_now())


@router.get("/ready", response_model=ReadyHealth, responses={503: {"model": ReadyHealth}})
async def ready(
    response: Response,
    service: WazuhDataService = Depends(get_data_service),
    settings: Settings = Depends(get_app_settings),
) -> ReadyHealth:
    try:
        cached = await service.readiness()
        version = compatibility(manager_version(cached.value), settings.target_agent_version)
        if not version.compatible:
            logging.getLogger(__name__).error(
                "target agent version %s is newer than manager %s",
                version.target,
                version.manager,
            )
            raise ValueError("target agent is newer than manager")
    except (WazuhApiError, ValueError):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadyHealth(status="not_ready", wazuh_api="unreachable", time=utc_now())
    return ReadyHealth(
        status="ready", wazuh_api="reachable", manager_version=version.manager, time=utc_now()
    )
