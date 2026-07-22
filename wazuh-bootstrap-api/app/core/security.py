"""API-key authentication dependencies."""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, status

from app.core.config import Settings


def api_key_matches(provided: str | None, expected: str) -> bool:
    candidate = provided or ""
    return secrets.compare_digest(candidate.encode(), expected.encode())


def _settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


async def require_client_key(request: Request) -> None:
    settings = _settings(request)
    if not api_key_matches(
        request.headers.get("X-API-Key"), settings.client_api_key.get_secret_value()
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


async def require_admin_key(request: Request) -> None:
    settings = _settings(request)
    if not api_key_matches(
        request.headers.get("X-Admin-API-Key"), settings.admin_api_key.get_secret_value()
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
