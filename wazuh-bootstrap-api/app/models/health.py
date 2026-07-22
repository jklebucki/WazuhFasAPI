"""Health response models."""

from datetime import datetime
from typing import Literal

from app.models.common import ApiModel


class LiveHealth(ApiModel):
    status: Literal["ok"] = "ok"
    service: str
    version: str
    time: datetime


class ReadyHealth(ApiModel):
    status: Literal["ready", "not_ready"]
    wazuh_api: Literal["reachable", "unreachable"]
    manager_version: str | None = None
    time: datetime
