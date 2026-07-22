"""Client bootstrap manifest endpoint."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.dependencies import get_app_settings, get_data_service
from app.core.config import Settings
from app.core.security import require_client_key
from app.models.common import utc_now
from app.models.manifest import ManagerManifest, Manifest, TargetAgent, WindowsManifest
from app.services.bootstrap import compatibility
from app.services.wazuh_data import WazuhDataService

router = APIRouter(prefix="/api/v1", tags=["bootstrap"])


@router.get(
    "/manifest",
    response_model=Manifest,
    dependencies=[Depends(require_client_key)],
    responses={401: {"description": "Unauthorized"}, 503: {"description": "Upstream unavailable"}},
)
async def manifest(
    response: Response,
    service: WazuhDataService = Depends(get_data_service),
    settings: Settings = Depends(get_app_settings),
) -> Manifest:
    cached = await service.manager()
    raw_version = cached.value.get("version")
    if not isinstance(raw_version, str):
        raise HTTPException(status_code=503, detail="Service Unavailable")
    versions = compatibility(raw_version, settings.target_agent_version)
    if not versions.compatible:
        logging.getLogger(__name__).error(
            "target agent version %s is newer than manager %s",
            versions.target,
            versions.manager,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service Unavailable"
        )
    revision = settings.target_agent_package_revision
    filename = f"wazuh-agent-{versions.target}-{revision}.msi"
    url = (
        str(settings.target_agent_msi_url)
        if settings.target_agent_msi_url
        else (f"https://packages.wazuh.com/4.x/windows/{filename}")
    )
    response.headers["Cache-Control"] = "private, max-age=30"
    if cached.stale:
        response.headers["Warning"] = '110 - "Response is stale"'
    now = utc_now()
    return Manifest(
        target_agent=TargetAgent(
            version=versions.target,
            package_revision=revision,
            full_package_version=f"{versions.target}-{revision}",
            msi_file_name=filename,
            download_url=url,
            sha256=settings.target_agent_sha256,
        ),
        manager=ManagerManifest(
            version=versions.manager,
            address=settings.wazuh_manager_address,
            communication_port=settings.wazuh_manager_port,
            registration_address=settings.wazuh_registration_address,
            registration_port=settings.wazuh_registration_port,
            compatible=True,
        ),
        windows=WindowsManifest(),
        generated_at=now,
        data_as_of=cached.data_as_of,
        stale=cached.stale,
    )
