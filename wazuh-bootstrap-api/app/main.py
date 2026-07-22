"""FastAPI application factory and process lifespan."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.routes import agents, groups, health, manifest
from app.clients.wazuh import (
    WazuhApiError,
    WazuhAuthenticationError,
    WazuhAuthorizationError,
    WazuhClient,
)
from app.core.config import Settings, get_settings
from app.core.logging import RequestMiddleware, configure_logging
from app.services.wazuh_data import WazuhDataService


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    configure_logging(app_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        timeout = httpx.Timeout(
            connect=app_settings.wazuh_api_connect_timeout_seconds,
            read=app_settings.wazuh_api_read_timeout_seconds,
            write=app_settings.wazuh_api_read_timeout_seconds,
            pool=app_settings.wazuh_api_connect_timeout_seconds,
        )
        async with httpx.AsyncClient(
            base_url=str(app_settings.wazuh_api_url).rstrip("/"),
            verify=app_settings.httpx_verify,
            timeout=timeout,
            follow_redirects=False,
        ) as http:
            client = WazuhClient(http, app_settings)
            app.state.data_service = WazuhDataService(client, app_settings)
            logging.getLogger(__name__).info("application started")
            if app_settings.app_env != "test":
                try:
                    await app.state.data_service.readiness()
                    logging.getLogger(__name__).info("initial Wazuh RBAC check succeeded")
                except Exception:
                    # Startup remains available for liveness and recovery; readiness stays failed.
                    logging.getLogger(__name__).warning("initial Wazuh RBAC check failed")
            yield
            logging.getLogger(__name__).info("application stopped")

    docs = "/docs" if app_settings.docs_enabled else None
    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        docs_url=docs,
        redoc_url="/redoc" if app_settings.docs_enabled else None,
        openapi_url="/openapi.json" if app_settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.add_middleware(RequestMiddleware)
    app.include_router(health.router)
    app.include_router(manifest.router)
    app.include_router(agents.router)
    app.include_router(groups.router)

    @app.exception_handler(WazuhApiError)
    async def upstream_error(request: Request, exc: WazuhApiError) -> JSONResponse:
        logging.getLogger(__name__).warning("controlled Wazuh upstream failure")
        if isinstance(exc, WazuhAuthenticationError | WazuhAuthorizationError):
            request.state.upstream_status = "denied"
        else:
            request.state.upstream_status = "unavailable"
        return JSONResponse(status_code=503, content={"detail": "Service Unavailable"})

    return app


app = create_app()
