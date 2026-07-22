import httpx
import respx
from fastapi.testclient import TestClient
from pydantic import AnyHttpUrl

from app.main import create_app
from tests.conftest import CLIENT_KEY, token, wazuh_response


@respx.mock
def test_manifest_explicit_version_generated_url(client: TestClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/manager/info").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"version": "Wazuh v4.15.0"}]))
    )
    assert client.get("/api/v1/manifest").status_code == 401
    response = client.get("/api/v1/manifest", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["targetAgent"]["version"] == "4.14.6"
    assert body["targetAgent"]["downloadUrl"].endswith("wazuh-agent-4.14.6-1.msi")
    assert body["manager"]["compatible"] is True
    assert response.headers["cache-control"] == "private, max-age=30"


@respx.mock
def test_manifest_rejects_newer_agent(client: TestClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/manager/info").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"version": "4.13.0"}]))
    )
    response = client.get("/api/v1/manifest", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 503
    assert response.json() == {"detail": "Service Unavailable"}


@respx.mock
def test_manifest_auto_version_explicit_url_and_sha(settings) -> None:  # type: ignore[no-untyped-def]
    settings.target_agent_version = "auto"
    settings.target_agent_msi_url = AnyHttpUrl("https://downloads.example.test/wazuh.msi")
    settings.target_agent_sha256 = "a" * 64
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/manager/info").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"version": "4.15.1"}]))
    )
    with TestClient(create_app(settings)) as local_client:
        response = local_client.get("/api/v1/manifest", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 200
    assert response.json()["targetAgent"] == {
        "version": "4.15.1",
        "packageRevision": "1",
        "fullPackageVersion": "4.15.1-1",
        "msiFileName": "wazuh-agent-4.15.1-1.msi",
        "downloadUrl": "https://downloads.example.test/wazuh.msi",
        "sha256": "a" * 64,
    }
