import time

import httpx
import respx
from fastapi.testclient import TestClient

from tests.conftest import CLIENT_KEY, token, wazuh_response


def mock_auth() -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )


@respx.mock
def test_agent_exists_casefold_fqdn_and_ip(
    client: TestClient, agent_raw: dict[str, object]
) -> None:
    mock_auth()
    route = respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([agent_raw]))
    )
    response = client.get("/api/v1/agents/lap006.ad.example.", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["queryName"] == "lap006"
    assert body["agent"]["name"] == "LAP006"
    assert body["agent"]["lastKnownIp"] == "192.168.29.20"
    assert body["agent"]["registrationIp"] == "any"
    assert body["agent"]["versionState"] == "current"
    assert route.calls[0].request.url.params["name"] == "lap006"


@respx.mock
def test_missing_agent_and_manager_record_ignored(client: TestClient) -> None:
    mock_auth()
    respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"id": "000", "name": "MISSING"}]))
    )
    response = client.get("/api/v1/agents/MISSING", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 200
    assert response.json()["registered"] is False
    assert response.json()["agent"] is None


@respx.mock
def test_duplicates_return_safe_409(client: TestClient, agent_raw: dict[str, object]) -> None:
    mock_auth()
    duplicate = agent_raw | {"id": "124", "name": "lap006", "ip": "10.0.0.2"}
    respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([agent_raw, duplicate]))
    )
    response = client.get("/api/v1/agents/LAP006", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 409
    body = response.json()
    assert body["duplicateCount"] == 2
    assert body["agent"] is None
    assert "lastKnownIp" not in body["duplicates"][0]


def test_bad_hostname_and_wrong_key(client: TestClient) -> None:
    for hostname in ("bad name", "../secret", "a" * 64):
        response = client.get(f"/api/v1/agents/{hostname}", headers={"X-API-Key": CLIENT_KEY})
        assert response.status_code in (400, 404)
    response = client.get("/api/v1/agents/LAP006", headers={"X-API-Key": "bad"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


@respx.mock
def test_lookup_uses_fresh_cache(client: TestClient, agent_raw: dict[str, object]) -> None:
    mock_auth()
    route = respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([agent_raw]))
    )
    for _ in range(2):
        assert (
            client.get("/api/v1/agents/LAP006", headers={"X-API-Key": CLIENT_KEY}).status_code
            == 200
        )
    assert route.call_count == 1


@respx.mock
def test_upstream_failure_is_sanitized(client: TestClient) -> None:
    mock_auth()
    respx.get("https://wazuh.local:55000/agents").mock(return_value=httpx.Response(503))
    response = client.get("/api/v1/agents/LAP006", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 503
    assert response.json() == {"detail": "Service Unavailable"}
    assert "wazuh.local" not in response.text


@respx.mock
def test_lookup_falls_back_to_stale_cache(client: TestClient, agent_raw: dict[str, object]) -> None:
    mock_auth()
    client.app.state.settings.agents_cache_ttl_seconds = 0
    route = respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([agent_raw]))
    )
    assert client.get("/api/v1/agents/LAP006", headers={"X-API-Key": CLIENT_KEY}).status_code == 200
    time.sleep(0.01)
    route.mock(return_value=httpx.Response(503))
    response = client.get("/api/v1/agents/LAP006", headers={"X-API-Key": CLIENT_KEY})
    assert response.status_code == 200
    assert response.json()["stale"] is True
    assert response.headers["warning"] == '110 - "Response is stale"'
