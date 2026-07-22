from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def base() -> dict[str, object]:
    return {
        "WAZUH_API_URL": "https://localhost:55000",
        "WAZUH_API_USERNAME": "reader",
        "WAZUH_API_PASSWORD": "password",
        "WAZUH_MANAGER_ADDRESS": "manager",
        "WAZUH_REGISTRATION_ADDRESS": "manager",
        "CLIENT_API_KEY": "c" * 32,
        "ADMIN_API_KEY": "a" * 32,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("CLIENT_API_KEY", "CHANGE_ME"),
        ("WAZUH_API_PASSWORD", "CHANGE_ME"),
        ("CLIENT_API_KEY", "short"),
        ("TARGET_AGENT_SHA256", "not-a-sha"),
        ("WAZUH_API_URL", "not a url"),
        ("TARGET_AGENT_MSI_URL", "http://insecure.example/wazuh.msi"),
    ],
)
def test_invalid_settings(field: str, value: str) -> None:
    values = base()
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]


def test_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLIENT_API_KEY")
    values = base()
    del values["CLIENT_API_KEY"]
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]


def test_identical_keys() -> None:
    values = base()
    values["ADMIN_API_KEY"] = values["CLIENT_API_KEY"]
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]


def test_auto_empty_url_and_lowercase_sha() -> None:
    values = base() | {
        "TARGET_AGENT_VERSION": "auto",
        "TARGET_AGENT_MSI_URL": "",
        "TARGET_AGENT_SHA256": "A" * 64,
    }
    settings = Settings(**values)  # type: ignore[arg-type]
    assert settings.target_agent_version == "auto"
    assert settings.target_agent_msi_url is None
    assert settings.target_agent_sha256 == "a" * 64


def test_tls_system_ca_and_missing_explicit_ca(tmp_path: Path) -> None:
    settings = Settings(**(base() | {"WAZUH_API_VERIFY_TLS": True}))  # type: ignore[arg-type]
    assert settings.httpx_verify is True
    with pytest.raises(ValidationError):
        Settings(  # type: ignore[arg-type]
            **(
                base()
                | {
                    "WAZUH_API_VERIFY_TLS": True,
                    "WAZUH_API_CA_FILE": tmp_path / "missing.pem",
                }
            )
        )
