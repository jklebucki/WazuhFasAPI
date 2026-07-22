"""API-key authentication dependencies."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import Settings

client_api_key = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ClientApiKey",
    description="Client key used by bootstrap consumers and agent lookup.",
    auto_error=False,
)
admin_api_key = APIKeyHeader(
    name="X-Admin-API-Key",
    scheme_name="AdminApiKey",
    description="Administrator key used by agent and group inventory endpoints.",
    auto_error=False,
)


def api_key_matches(provided: str | None, expected: str) -> bool:
    candidate = provided or ""
    return secrets.compare_digest(candidate.encode(), expected.encode())


def _settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


async def require_client_key(
    request: Request,
    provided: Annotated[str | None, Security(client_api_key)],
) -> None:
    settings = _settings(request)
    if not api_key_matches(provided, settings.client_api_key.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


async def require_admin_key(
    request: Request,
    provided: Annotated[str | None, Security(admin_api_key)],
) -> None:
    settings = _settings(request)
    if not api_key_matches(provided, settings.admin_api_key.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
