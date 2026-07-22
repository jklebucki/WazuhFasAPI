import httpx
import respx
from fastapi.testclient import TestClient

from tests.conftest import token, wazuh_response


@respx.mock
def test_liveness_security_headers_and_docs_disabled(client: TestClient) -> None:
    response = client.get("/health/live", headers={"X-Request-ID": "test-request-1"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-request-id"] == "test-request-1"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'"
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@respx.mock
def test_ready_success_and_failure(client: TestClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    manager = respx.get("https://wazuh.local:55000/manager/info").mock(
        return_value=httpx.Response(200, json=wazuh_response([{"version": "Wazuh v4.14.6"}]))
    )
    respx.get("https://wazuh.local:55000/agents").mock(
        return_value=httpx.Response(200, json=wazuh_response([]))
    )
    respx.get("https://wazuh.local:55000/groups").mock(
        return_value=httpx.Response(200, json=wazuh_response([]))
    )
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["managerVersion"] == "4.14.6"
    client.app.state.data_service.readiness_cache.clear()
    manager.mock(return_value=httpx.Response(503))
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "wazuhApi": "unreachable",
        "managerVersion": None,
        "time": response.json()["time"],
    }
    assert "wazuh.local" not in response.text
