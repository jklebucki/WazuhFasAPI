# ruff: noqa: I001

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import jwt
import pytest
from fastapi.testclient import TestClient

os.environ.update(
    {
        "APP_ENV": "test",
        "WAZUH_API_URL": "https://wazuh.local:55000",
        "WAZUH_API_USERNAME": "reader",
        "WAZUH_API_PASSWORD": "safe-test-password",
        "WAZUH_MANAGER_ADDRESS": "192.168.21.15",
        "WAZUH_REGISTRATION_ADDRESS": "192.168.21.15",
        "CLIENT_API_KEY": "client-" + "c" * 40,
        "ADMIN_API_KEY": "admin-" + "a" * 40,
        "TARGET_AGENT_VERSION": "4.14.6",
        "TARGET_AGENT_MSI_URL": "",
    }
)

from app.core.config import Settings
from app.main import create_app


CLIENT_KEY = "client-" + "c" * 40
ADMIN_KEY = "admin-" + "a" * 40


def token(expires_in: int = 900) -> str:
    return jwt.encode({"exp": int(time.time()) + expires_in}, "test", algorithm="HS256")


def wazuh_response(items: list[dict[str, object]], total: int | None = None) -> dict[str, object]:
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items) if total is None else total,
        },
        "error": 0,
    }


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def agent_raw() -> dict[str, object]:
    return {
        "id": "123",
        "name": "LAP006",
        "group": ["ADMINISTRACJA"],
        "status": "disconnected",
        "status_code": 1,
        "version": "Wazuh v4.14.6",
        "ip": "192.168.29.20",
        "registerIP": "any",
        "lastKeepAlive": "2026-07-20T10:15:00Z",
        "dateAdd": "2025-03-10T08:00:00Z",
        "manager": "wazuh-srv",
        "node_name": "node01",
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Pro", "version": "10"},
    }
