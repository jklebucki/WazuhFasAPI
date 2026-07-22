import httpx
import respx
from fastapi.testclient import TestClient

from tests.conftest import ADMIN_KEY, token, wazuh_response


@respx.mock
def test_groups_and_group_detail(client: TestClient, agent_raw: dict[str, object]) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    groups = respx.get("https://wazuh.local:55000/groups").mock(
        return_value=httpx.Response(
            200, json=wazuh_response([{"name": "ADMINISTRACJA", "count": 25}])
        )
    )
    agents = respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([agent_raw]))
    )
    response = client.get("/api/v1/groups", headers={"X-Admin-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    assert response.json()["items"] == [{"name": "ADMINISTRACJA", "agentCount": 25}]
    response = client.get("/api/v1/groups/administracja", headers={"X-Admin-API-Key": ADMIN_KEY})
    assert response.status_code == 200
    assert response.json()["agents"][0]["name"] == "LAP006"
    assert groups.call_count == 1
    assert agents.call_count == 1


@respx.mock
def test_group_not_found(client: TestClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/groups").mock(
        return_value=httpx.Response(200, json=wazuh_response([]))
    )
    response = client.get("/api/v1/groups/missing", headers={"X-Admin-API-Key": ADMIN_KEY})
    assert response.status_code == 404
