import httpx
import respx
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
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


def test_docs_enabled_exposes_ui_and_api_key_security_schemes(settings: Settings) -> None:
    docs_settings = settings.model_copy(update={"docs_enabled": True})
    with TestClient(create_app(docs_settings)) as docs_client:
        docs = docs_client.get("/docs")
        redoc = docs_client.get("/redoc")
        schema_response = docs_client.get("/openapi.json")

    assert docs.status_code == 200
    assert redoc.status_code == 200
    assert "https://cdn.jsdelivr.net" in docs.headers["content-security-policy"]
    assert "connect-src 'self'" in docs.headers["content-security-policy"]
    assert schema_response.status_code == 200

    schema = schema_response.json()
    schemes = schema["components"]["securitySchemes"]
    assert schemes["ClientApiKey"] == {
        "type": "apiKey",
        "description": "Client key used by bootstrap consumers and agent lookup.",
        "in": "header",
        "name": "X-API-Key",
    }
    assert schemes["AdminApiKey"] == {
        "type": "apiKey",
        "description": "Administrator key used by agent and group inventory endpoints.",
        "in": "header",
        "name": "X-Admin-API-Key",
    }
    assert schema["paths"]["/api/v1/manifest"]["get"]["security"] == [{"ClientApiKey": []}]
    assert schema["paths"]["/api/v1/agents/{hostname}"]["get"]["security"] == [{"ClientApiKey": []}]
    assert schema["paths"]["/api/v1/agents"]["get"]["security"] == [{"AdminApiKey": []}]
    assert schema["paths"]["/api/v1/groups"]["get"]["security"] == [{"AdminApiKey": []}]


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
