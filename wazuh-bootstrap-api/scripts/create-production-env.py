#!/usr/bin/env python3
"""Create a production env atomically from separately protected secret files."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def read_api_keys(path: Path) -> tuple[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if not separator:
            raise ValueError("invalid API key file")
        values[key] = value
    client = values.get("CLIENT_API_KEY", "")
    admin = values.get("ADMIN_API_KEY", "")
    if len(client) < 32 or len(admin) < 32 or client == admin:
        raise ValueError("API keys are missing, too short, or identical")
    return client, admin


def env_quote(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("environment values must be single-line strings")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_env(password: str, client_key: str, admin_key: str, sha256: str) -> str:
    values: list[tuple[str, str]] = [
        ("APP_NAME", "Wazuh Bootstrap API"),
        ("APP_ENV", "production"),
        ("APP_VERSION", "1.0.0"),
        ("BIND_HOST", "192.168.21.15"),
        ("BIND_PORT", "8765"),
        ("UVICORN_WORKERS", "1"),
        ("WAZUH_API_URL", "https://localhost:55000"),
        ("WAZUH_API_USERNAME", "wazuh-wui"),
        ("WAZUH_API_PASSWORD", password),
        ("WAZUH_API_VERIFY_TLS", "true"),
        ("WAZUH_API_CA_FILE", "/etc/wazuh-bootstrap-api-wazuh-ca.pem"),
        ("WAZUH_API_CONNECT_TIMEOUT_SECONDS", "3"),
        ("WAZUH_API_READ_TIMEOUT_SECONDS", "10"),
        ("WAZUH_MANAGER_ADDRESS", "192.168.21.15"),
        ("WAZUH_MANAGER_PORT", "1514"),
        ("WAZUH_REGISTRATION_ADDRESS", "192.168.21.15"),
        ("WAZUH_REGISTRATION_PORT", "1515"),
        ("TARGET_AGENT_VERSION", "4.14.6"),
        ("TARGET_AGENT_PACKAGE_REVISION", "1"),
        (
            "TARGET_AGENT_MSI_URL",
            "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi",
        ),
        ("TARGET_AGENT_SHA256", sha256),
        ("CLIENT_API_KEY", client_key),
        ("ADMIN_API_KEY", admin_key),
        ("MANAGER_CACHE_TTL_SECONDS", "60"),
        ("AGENTS_CACHE_TTL_SECONDS", "30"),
        ("GROUPS_CACHE_TTL_SECONDS", "60"),
        ("UPSTREAM_STALE_CACHE_SECONDS", "300"),
        ("DOCS_ENABLED", "false"),
        ("LOG_LEVEL", "INFO"),
        ("TRUST_PROXY_HEADERS", "true"),
        ("FORWARDED_ALLOW_IPS", "192.168.21.17"),
    ]
    return "\n".join(f"{key}={env_quote(value)}" for key, value in values) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wazuh-password-file", type=Path, required=True)
    parser.add_argument("--api-keys-file", type=Path, required=True)
    parser.add_argument("--msi-sha256", required=True)
    args = parser.parse_args()

    password = args.wazuh_password_file.read_text(encoding="utf-8")
    if not password:
        raise ValueError("Wazuh API password file is empty")
    client_key, admin_key = read_api_keys(args.api_keys_file)
    sha256 = args.msi_sha256.lower()
    if len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256):
        raise ValueError("MSI SHA-256 is invalid")
    content = build_env(password, client_key, admin_key, sha256)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, content.encode())
    finally:
        os.close(descriptor)
    os.chmod(args.output, 0o600)
    print(f"Production environment written to {args.output} (secret values not displayed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
