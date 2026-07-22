from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from app.clients.wazuh import (
    WazuhApiError,
    WazuhAuthenticationError,
    WazuhAuthorizationError,
    WazuhClient,
    WazuhInvalidResponseError,
    WazuhUnavailableError,
)
from app.core.config import Settings
from tests.conftest import token, wazuh_response


@pytest.fixture
async def wazuh(settings: Settings):  # type: ignore[no-untyped-def]
    async with httpx.AsyncClient(base_url="https://wazuh.local:55000") as http:
        yield WazuhClient(http, settings)


@pytest.mark.asyncio
@respx.mock
async def test_raw_auth_and_token_cache(wazuh: WazuhClient) -> None:
    route = respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    first, second = await asyncio.gather(wazuh.authenticate(), wazuh.authenticate())
    assert first == second
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_json_auth_and_refresh_before_expiry(wazuh: WazuhClient) -> None:
    route = respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, json={"data": {"token": token(30)}})
    )
    await wazuh.authenticate()
    await wazuh.authenticate()
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_retry_once_after_401(wazuh: WazuhClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        side_effect=[
            httpx.Response(200, text=token(), headers={"content-type": "text/plain"}),
            httpx.Response(200, text=token(), headers={"content-type": "text/plain"}),
        ]
    )
    route = respx.get("https://wazuh.local:55000/manager/info").mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json=wazuh_response([{"version": "4.14.6"}])),
        ]
    )
    assert (await wazuh.manager_info())["version"] == "4.14.6"
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_parallel_401_responses_share_one_refresh(wazuh: WazuhClient) -> None:
    old_token = token(900)
    new_token = token(1200)
    auth = respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        side_effect=[
            httpx.Response(200, text=old_token, headers={"content-type": "text/plain"}),
            httpx.Response(200, text=new_token, headers={"content-type": "text/plain"}),
        ]
    )
    both_old = asyncio.Event()
    old_requests = 0

    async def manager_response(request: httpx.Request) -> httpx.Response:
        nonlocal old_requests
        if request.headers["Authorization"] == f"Bearer {old_token}":
            old_requests += 1
            if old_requests == 2:
                both_old.set()
            await both_old.wait()
            return httpx.Response(401)
        return httpx.Response(200, json=wazuh_response([{"version": "4.14.6"}]))

    respx.get("https://wazuh.local:55000/manager/info").mock(side_effect=manager_response)
    await asyncio.gather(wazuh.manager_info(), wazuh.manager_info())
    assert auth.call_count == 2


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    ("status_code", "error"),
    [(403, WazuhAuthorizationError), (429, WazuhUnavailableError), (500, WazuhUnavailableError)],
)
async def test_http_errors(wazuh: WazuhClient, status_code: int, error: type[Exception]) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/manager/info").mock(
        return_value=httpx.Response(status_code)
    )
    with pytest.raises(error):
        await wazuh.manager_info()


@pytest.mark.asyncio
@respx.mock
async def test_second_401_is_auth_error(wazuh: WazuhClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    respx.get("https://wazuh.local:55000/manager/info").mock(return_value=httpx.Response(401))
    with pytest.raises(WazuhAuthenticationError):
        await wazuh.manager_info()


@pytest.mark.asyncio
@respx.mock
async def test_timeout_invalid_json_and_upstream_error(wazuh: WazuhClient) -> None:
    auth = respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    route = respx.get("https://wazuh.local:55000/manager/info")
    route.mock(side_effect=httpx.ConnectTimeout("timeout"))
    with pytest.raises(WazuhUnavailableError):
        await wazuh.manager_info()
    route.mock(return_value=httpx.Response(200, text="not-json"))
    with pytest.raises(WazuhInvalidResponseError):
        await wazuh.manager_info()
    route.mock(return_value=httpx.Response(200, json={"error": 1}))
    with pytest.raises(WazuhApiError):
        await wazuh.manager_info()
    assert auth.called


@pytest.mark.asyncio
@respx.mock
async def test_agent_and_group_pagination(wazuh: WazuhClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    agents = respx.get("https://wazuh.local:55000/agents").mock(
        side_effect=[
            httpx.Response(200, json=wazuh_response([{"id": "1"}], total=2)),
            httpx.Response(200, json=wazuh_response([{"id": "2"}], total=2)),
        ]
    )
    assert len(await wazuh.all_agents()) == 2
    assert agents.call_count == 2
    groups = respx.get("https://wazuh.local:55000/groups").mock(
        side_effect=[
            httpx.Response(200, json=wazuh_response([{"name": "a"}], total=2)),
            httpx.Response(200, json=wazuh_response([{"name": "b"}], total=2)),
        ]
    )
    assert len(await wazuh.all_groups()) == 2
    assert groups.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_invalid_auth_token_and_response_shapes(wazuh: WazuhClient) -> None:
    auth = respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true")
    auth.mock(return_value=httpx.Response(401))
    with pytest.raises(WazuhAuthenticationError):
        await wazuh.authenticate()
    auth.mock(return_value=httpx.Response(200, json={"data": {}}))
    with pytest.raises(WazuhInvalidResponseError):
        await wazuh.authenticate(force=True)
    auth.mock(
        return_value=httpx.Response(200, text="not-a-jwt", headers={"content-type": "text/plain"})
    )
    with pytest.raises(WazuhInvalidResponseError):
        await wazuh.authenticate(force=True)


@pytest.mark.asyncio
@respx.mock
async def test_invalid_page_shapes_and_empty_manager(wazuh: WazuhClient) -> None:
    respx.post("https://wazuh.local:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text=token(), headers={"content-type": "text/plain"})
    )
    route = respx.get("https://wazuh.local:55000/manager/info")
    route.mock(return_value=httpx.Response(200, json={"error": 0, "data": {}}))
    with pytest.raises(WazuhInvalidResponseError):
        await wazuh.manager_info()
    route.mock(return_value=httpx.Response(200, json=wazuh_response([])))
    with pytest.raises(WazuhInvalidResponseError):
        await wazuh.manager_info()
