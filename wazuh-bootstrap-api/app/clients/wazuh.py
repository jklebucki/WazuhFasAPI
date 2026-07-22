"""Strict read-only client for the Wazuh Server API."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import httpx
import jwt

from app.core.config import Settings

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]

AGENT_SELECT = (
    "id,name,group,status,status_code,version,ip,registerIP,lastKeepAlive,dateAdd,"
    "manager,node_name,os.platform,os.name,os.version"
)


class WazuhApiError(RuntimeError):
    """Controlled upstream API failure."""


class WazuhAuthenticationError(WazuhApiError):
    """Wazuh credentials or token were rejected."""


class WazuhAuthorizationError(WazuhApiError):
    """Configured Wazuh account lacks required permissions."""


class WazuhUnavailableError(WazuhApiError):
    """Wazuh is temporarily unavailable or rate limited."""


class WazuhInvalidResponseError(WazuhApiError):
    """Wazuh returned an unexpected response."""


@dataclass(frozen=True, slots=True)
class Page:
    items: list[JsonObject]
    total: int


class WazuhClient:
    """Allow-listed Wazuh API client; no mutating methods are exposed."""

    def __init__(self, http: httpx.AsyncClient, settings: Settings) -> None:
        self._http = http
        self._settings = settings
        self._token: str | None = None
        self._token_expiry = 0.0
        self._auth_lock = asyncio.Lock()

    async def authenticate(self, *, force: bool = False) -> str:
        if not force and self._token_is_fresh():
            return cast(str, self._token)
        async with self._auth_lock:
            if not force and self._token_is_fresh():
                return cast(str, self._token)
            try:
                response = await self._http.post(
                    "/security/user/authenticate",
                    params={"raw": "true"},
                    auth=(
                        self._settings.wazuh_api_username,
                        self._settings.wazuh_api_password.get_secret_value(),
                    ),
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                raise WazuhUnavailableError("Wazuh authentication endpoint is unavailable") from exc
            if response.status_code == 401:
                raise WazuhAuthenticationError("Wazuh authentication failed")
            if response.status_code == 403:
                raise WazuhAuthorizationError("Wazuh authentication is not authorized")
            if response.status_code >= 500 or response.status_code == 429:
                raise WazuhUnavailableError("Wazuh authentication endpoint is unavailable")
            if not response.is_success:
                raise WazuhAuthenticationError("Wazuh authentication failed")
            token = self._extract_token(response)
            self._token = token
            self._token_expiry = self._read_expiry(token)
            logging.getLogger(__name__).info("Wazuh JWT obtained or refreshed")
            return token

    def _token_is_fresh(self) -> bool:
        return self._token is not None and time.time() < self._token_expiry - 60

    @staticmethod
    def _read_expiry(token: str) -> float:
        try:
            payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            expiry = payload.get("exp")
            if not isinstance(expiry, int | float):
                raise ValueError
            return float(expiry)
        except (jwt.PyJWTError, ValueError) as exc:
            raise WazuhInvalidResponseError(
                "Wazuh returned a token without a valid expiry"
            ) from exc

    @staticmethod
    def _extract_token(response: httpx.Response) -> str:
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type:
            raw_token = response.text.strip().strip('"')
            if raw_token:
                return raw_token
        try:
            body = response.json()
            data = body.get("data") if isinstance(body, dict) else None
            token: object = data.get("token") if isinstance(data, dict) else None
        except ValueError as exc:
            raise WazuhInvalidResponseError(
                "Wazuh returned an invalid authentication response"
            ) from exc
        if not isinstance(token, str) or not token:
            raise WazuhInvalidResponseError("Wazuh authentication response contains no token")
        return token

    async def _get(self, path: str, params: Mapping[str, str | int] | None = None) -> JsonObject:
        token = await self.authenticate()
        response = await self._send_get(path, token, params)
        if response.status_code == 401:
            token = await self._refresh_rejected_token(token)
            response = await self._send_get(path, token, params)
            if response.status_code == 401:
                raise WazuhAuthenticationError("Wazuh rejected the refreshed token")
        if response.status_code == 403:
            raise WazuhAuthorizationError("Wazuh denied access to a required resource")
        if response.status_code == 429 or response.status_code >= 500:
            raise WazuhUnavailableError("Wazuh API is temporarily unavailable")
        if not response.is_success:
            raise WazuhApiError("Wazuh API request failed")
        try:
            body = response.json()
        except ValueError as exc:
            raise WazuhInvalidResponseError("Wazuh returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise WazuhInvalidResponseError("Wazuh returned an invalid response structure")
        error = body.get("error", 0)
        if error != 0:
            raise WazuhApiError("Wazuh reported an application error")
        return cast(JsonObject, body)

    async def _refresh_rejected_token(self, rejected_token: str) -> str:
        async with self._auth_lock:
            if self._token is not None and self._token != rejected_token and self._token_is_fresh():
                return self._token
            self._token = None
            self._token_expiry = 0.0
            # The lock is already held, so perform the small authentication exchange inline.
            try:
                response = await self._http.post(
                    "/security/user/authenticate",
                    params={"raw": "true"},
                    auth=(
                        self._settings.wazuh_api_username,
                        self._settings.wazuh_api_password.get_secret_value(),
                    ),
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                raise WazuhUnavailableError("Wazuh authentication endpoint is unavailable") from exc
            if not response.is_success:
                if response.status_code == 403:
                    raise WazuhAuthorizationError("Wazuh authentication is not authorized")
                if response.status_code == 429 or response.status_code >= 500:
                    raise WazuhUnavailableError("Wazuh authentication endpoint is unavailable")
                raise WazuhAuthenticationError("Wazuh authentication failed")
            token = self._extract_token(response)
            self._token = token
            self._token_expiry = self._read_expiry(token)
            logging.getLogger(__name__).info("Wazuh JWT refreshed after upstream rejection")
            return token

    async def _send_get(
        self, path: str, token: str, params: Mapping[str, str | int] | None
    ) -> httpx.Response:
        try:
            return await self._http.get(
                path, params=params, headers={"Authorization": f"Bearer {token}"}
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise WazuhUnavailableError("Wazuh API is unavailable") from exc

    @staticmethod
    def _page(body: JsonObject) -> Page:
        data = body.get("data")
        if not isinstance(data, dict):
            raise WazuhInvalidResponseError("Wazuh response has no data object")
        affected = data.get("affected_items")
        total = data.get("total_affected_items")
        if not isinstance(affected, list) or not isinstance(total, int):
            raise WazuhInvalidResponseError("Wazuh response has invalid pagination fields")
        items: list[JsonObject] = []
        for item in affected:
            if not isinstance(item, dict):
                raise WazuhInvalidResponseError("Wazuh response contains an invalid item")
            items.append(item)
        return Page(items, total)

    async def manager_info(self) -> JsonObject:
        body = await self._get("/manager/info")
        page = self._page(body)
        if not page.items:
            raise WazuhInvalidResponseError("Wazuh manager info is empty")
        return page.items[0]

    async def agents_by_name(self, hostname: str) -> list[JsonObject]:
        body = await self._get("/agents", {"name": hostname, "select": AGENT_SELECT, "limit": 100})
        return self._page(body).items

    async def all_agents(self) -> list[JsonObject]:
        return await self._all_pages(
            "/agents", {"select": AGENT_SELECT, "sort": "name", "limit": 500}
        )

    async def all_groups(self) -> list[JsonObject]:
        return await self._all_pages("/groups", {"sort": "name", "limit": 500})

    async def readiness_info(self) -> JsonObject:
        """Verify all required read permissions with bounded one-item queries."""
        manager = await self.manager_info()
        await self._get("/agents", {"limit": 1, "select": "id"})
        await self._get("/groups", {"limit": 1})
        return manager

    async def _all_pages(self, path: str, params: dict[str, str | int]) -> list[JsonObject]:
        offset = 0
        items: list[JsonObject] = []
        while True:
            page_params = {**params, "offset": offset}
            page = self._page(await self._get(path, page_params))
            items.extend(page.items)
            if len(items) >= page.total or not page.items:
                return items
            offset += len(page.items)
