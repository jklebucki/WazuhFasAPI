"""External API clients."""

from app.clients.wazuh import (
    WazuhApiError,
    WazuhAuthenticationError,
    WazuhAuthorizationError,
    WazuhInvalidResponseError,
    WazuhUnavailableError,
)

__all__ = [
    "WazuhApiError",
    "WazuhAuthenticationError",
    "WazuhAuthorizationError",
    "WazuhInvalidResponseError",
    "WazuhUnavailableError",
]
