from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _subprocess_environment() -> dict[str, str]:
    """Keep pytest-cov's parent configuration out of independently executed scripts."""
    return {key: value for key, value in os.environ.items() if not key.startswith("COV_CORE_")}


def test_installer_stops_service_before_swap_and_restarts_after_validation() -> None:
    installer = (PROJECT_ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")

    stop = installer.rindex('systemctl stop "$service_name"')
    swap = installer.index('mv -- "$install_dir" "$backup_dir"')
    validation = installer.index('"$install_dir/scripts/validate-config.py"')
    restart = installer.index('systemctl restart "$service_name"')

    assert stop < swap < validation < restart
    assert "Deployment failed; restoring the previous application version." in installer
    assert 'systemctl start "$service_name"' in installer
    assert "/var/log/wazuh-bootstrap-api" in installer
    assert "Full installer log:" in installer


def test_enrollment_check_never_prints_password_and_supports_safe_comparison() -> None:
    checker = (PROJECT_ROOT / "scripts" / "check-wazuh-enrollment.sh").read_text(encoding="utf-8")

    assert "<use_password>yes</use_password>" in checker
    assert "cmp -s --" in checker
    assert "wazuh-authd -t" in checker
    assert "Password has a non-empty, GPO-compatible format." in checker
    assert "printf '%s\\n' \"$password\"" not in checker
    assert 'echo "$password"' not in checker
    assert 'cat "$password_file"' not in checker


def test_validate_config_can_import_app_from_another_working_directory(tmp_path: Path) -> None:
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "\n".join(
            (
                'APP_ENV="production"',
                'BIND_PORT="8765"',
                'UVICORN_WORKERS="1"',
                'WAZUH_API_URL="https://localhost:55000"',
                'WAZUH_API_USERNAME="reader"',
                'WAZUH_API_PASSWORD="a-safe-password"',
                'WAZUH_API_VERIFY_TLS="false"',
                'WAZUH_API_CONNECT_TIMEOUT_SECONDS="3"',
                'WAZUH_API_READ_TIMEOUT_SECONDS="10"',
                'WAZUH_MANAGER_ADDRESS="192.168.21.15"',
                'WAZUH_MANAGER_PORT="1514"',
                'WAZUH_REGISTRATION_ADDRESS="192.168.21.15"',
                'WAZUH_REGISTRATION_PORT="1515"',
                f'CLIENT_API_KEY="{"c" * 40}"',
                f'ADMIN_API_KEY="{"a" * 40}"',
                'TARGET_AGENT_VERSION="4.14.6"',
                'TARGET_AGENT_MSI_URL=""',
                'TARGET_AGENT_SHA256=""',
                'MANAGER_CACHE_TTL_SECONDS="60"',
                'AGENTS_CACHE_TTL_SECONDS="30"',
                'GROUPS_CACHE_TTL_SECONDS="60"',
                'UPSTREAM_STALE_CACHE_SECONDS="300"',
                'DOCS_ENABLED="true"',
                'TRUST_PROXY_HEADERS="true"',
            )
        ),
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603 - executable and arguments are test-controlled
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "validate-config.py"),
            "--env-file",
            str(env_file),
            "--import-app",
        ],
        cwd=tmp_path,
        env=_subprocess_environment(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Configuration is valid" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="production smoke script runs on Linux")
def test_smoke_test_accepts_crlf_environment_file(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash is not None
    env_file = tmp_path / "production.env"
    env_file.write_bytes(
        b'BIND_HOST="192.168.21.15"\r\n'
        b'BIND_PORT="8765"\r\n' + b'CLIENT_API_KEY="' + b"c" * 40 + b'"\r\n'
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl_log = tmp_path / "curl.log"
    curl_stub = bin_dir / "curl"
    curl_stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>"$CURL_LOG"\n', encoding="utf-8")
    curl_stub.chmod(0o755)
    process_env = _subprocess_environment()
    process_env["PATH"] = f"{bin_dir}{os.pathsep}{process_env['PATH']}"
    process_env["CURL_LOG"] = str(curl_log)

    result = subprocess.run(  # noqa: S603 - executable and arguments are test-controlled
        [
            bash,
            str(PROJECT_ROOT / "scripts" / "smoke-test.sh"),
            "--env-file",
            str(env_file),
            "--hostname",
            "LAP006",
            "--client-key",
            "c" * 40,
        ],
        cwd=tmp_path,
        env=process_env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    calls = curl_log.read_text(encoding="utf-8")
    assert "http://192.168.21.15:8765/health/live" in calls
    assert "http://192.168.21.15:8765/api/v1/agents/LAP006" in calls
