import httpx
import respx
from fastapi.testclient import TestClient

from tests.conftest import ADMIN_KEY, CLIENT_KEY, token, wazuh_response


@respx.mock
def test_admin_agent_list_filters_and_paginates(
    client: TestClient, agent_raw: dict[str, object]
) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    second = agent_raw | {"id": "124", "name": "LINUX01", "group": [], "os": {"platform": "linux"}}
    respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"id": "000"}, agent_raw, second]))
    )
    assert client.get("/api/v1/agents", headers={"X-API-Key": CLIENT_KEY}).status_code == 401
    response = client.get(
        "/api/v1/agents?platform=windows&group=administracja&limit=1",
        headers={"X-Admin-API-Key": ADMIN_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["name"] == "LAP006"
    assert body["items"][0]["lastKnownIp"] == "192.168.29.20"
    assert response.headers["cache-control"] == "no-store"


def test_admin_validation(client: TestClient) -> None:
    assert (
        client.get("/api/v1/agents?limit=501", headers={"X-Admin-API-Key": ADMIN_KEY}).status_code
        == 422
    )
    assert (
        client.get("/api/v1/agents?offset=-1", headers={"X-Admin-API-Key": ADMIN_KEY}).status_code
        == 422
    )
