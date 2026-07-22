"""Validated application configuration."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from environment variables or an optional dotenv file."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=True, extra="ignore"
    )

    app_name: str = Field("Wazuh Bootstrap API", alias="APP_NAME")
    app_env: Literal["development", "test", "production"] = Field("production", alias="APP_ENV")
    app_version: str = Field("1.0.0", alias="APP_VERSION")
    bind_host: str = Field("127.0.0.1", alias="BIND_HOST")
    bind_port: int = Field(8765, alias="BIND_PORT", ge=1, le=65535)
    uvicorn_workers: int = Field(1, alias="UVICORN_WORKERS", ge=1)

    wazuh_api_url: AnyHttpUrl = Field(alias="WAZUH_API_URL")
    wazuh_api_username: str = Field(alias="WAZUH_API_USERNAME", min_length=1)
    wazuh_api_password: SecretStr = Field(alias="WAZUH_API_PASSWORD")
    wazuh_api_verify_tls: bool = Field(False, alias="WAZUH_API_VERIFY_TLS")
    wazuh_api_ca_file: Path | None = Field(None, alias="WAZUH_API_CA_FILE")
    wazuh_api_connect_timeout_seconds: float = Field(
        3, alias="WAZUH_API_CONNECT_TIMEOUT_SECONDS", gt=0
    )
    wazuh_api_read_timeout_seconds: float = Field(10, alias="WAZUH_API_READ_TIMEOUT_SECONDS", gt=0)

    wazuh_manager_address: str = Field(alias="WAZUH_MANAGER_ADDRESS", min_length=1)
    wazuh_manager_port: int = Field(1514, alias="WAZUH_MANAGER_PORT", ge=1, le=65535)
    wazuh_registration_address: str = Field(alias="WAZUH_REGISTRATION_ADDRESS", min_length=1)
    wazuh_registration_port: int = Field(1515, alias="WAZUH_REGISTRATION_PORT", ge=1, le=65535)

    target_agent_version: str = Field("4.14.6", alias="TARGET_AGENT_VERSION")
    target_agent_package_revision: str = Field(
        "1", alias="TARGET_AGENT_PACKAGE_REVISION", min_length=1
    )
    target_agent_msi_url: AnyHttpUrl | None = Field(None, alias="TARGET_AGENT_MSI_URL")
    target_agent_sha256: str | None = Field(None, alias="TARGET_AGENT_SHA256")

    client_api_key: SecretStr = Field(alias="CLIENT_API_KEY")
    admin_api_key: SecretStr = Field(alias="ADMIN_API_KEY")

    manager_cache_ttl_seconds: int = Field(60, alias="MANAGER_CACHE_TTL_SECONDS", ge=1)
    agents_cache_ttl_seconds: int = Field(30, alias="AGENTS_CACHE_TTL_SECONDS", ge=1)
    groups_cache_ttl_seconds: int = Field(60, alias="GROUPS_CACHE_TTL_SECONDS", ge=1)
    upstream_stale_cache_seconds: int = Field(300, alias="UPSTREAM_STALE_CACHE_SECONDS", ge=0)
    docs_enabled: bool = Field(False, alias="DOCS_ENABLED")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    trust_proxy_headers: bool = Field(True, alias="TRUST_PROXY_HEADERS")

    @field_validator("wazuh_api_ca_file", mode="before")
    @classmethod
    def empty_ca_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("target_agent_msi_url", mode="before")
    @classmethod
    def empty_url_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("wazuh_api_url", "target_agent_msi_url")
    @classmethod
    def require_https(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        if value is not None and value.scheme != "https":
            raise ValueError("URL must use HTTPS")
        return value

    @field_validator("target_agent_sha256", mode="before")
    @classmethod
    def validate_sha256(cls, value: object) -> object:
        if value in (None, ""):
            return None
        text = str(value).lower()
        if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
            raise ValueError("TARGET_AGENT_SHA256 must contain exactly 64 hexadecimal characters")
        return text

    @field_validator("target_agent_version")
    @classmethod
    def validate_target_version(cls, value: str) -> str:
        if value.casefold() == "auto":
            return "auto"
        from app.services.bootstrap import normalize_version

        normalize_version(value)
        return value

    @model_validator(mode="after")
    def validate_secrets_and_tls(self) -> Self:
        password = self.wazuh_api_password.get_secret_value()
        client_key = self.client_api_key.get_secret_value()
        admin_key = self.admin_api_key.get_secret_value()
        for name, value in (
            ("WAZUH_API_PASSWORD", password),
            ("CLIENT_API_KEY", client_key),
            ("ADMIN_API_KEY", admin_key),
        ):
            if value == "CHANGE_ME":
                raise ValueError(f"{name} must be changed before startup")
        for name, value in (("CLIENT_API_KEY", client_key), ("ADMIN_API_KEY", admin_key)):
            if len(value) < 32:
                raise ValueError(f"{name} must contain at least 32 characters")
        if client_key == admin_key:
            raise ValueError("CLIENT_API_KEY and ADMIN_API_KEY must be different")
        if self.wazuh_api_verify_tls and self.wazuh_api_ca_file is not None:
            if not self.wazuh_api_ca_file.is_file():
                raise ValueError("WAZUH_API_CA_FILE does not exist or is not a file")
        return self

    @property
    def httpx_verify(self) -> bool | str:
        if not self.wazuh_api_verify_tls:
            return False
        return str(self.wazuh_api_ca_file) if self.wazuh_api_ca_file else True


@lru_cache
def get_settings() -> Settings:
    return Settings()
