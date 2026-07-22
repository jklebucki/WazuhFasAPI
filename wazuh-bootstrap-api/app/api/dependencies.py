"""FastAPI application dependencies."""

from fastapi import Request

from app.core.config import Settings
from app.services.wazuh_data import WazuhDataService


def get_data_service(request: Request) -> WazuhDataService:
    return request.app.state.data_service  # type: ignore[no-any-return]


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]
