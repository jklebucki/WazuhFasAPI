"""Agent response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.models.common import ApiModel


class OperatingSystem(ApiModel):
    platform: str | None = None
    name: str | None = None
    version: str | None = None


class Agent(ApiModel):
    id: str
    name: str
    groups: list[str] = Field(default_factory=list)
    status: str | None = None
    status_code: int | None = None
    version_raw: str | None = None
    version: str | None = None
    version_state: Literal["current", "outdated", "newer_than_target", "unknown"] = "unknown"
    last_known_ip: str | None = None
    registration_ip: str | None = None
    last_keep_alive: datetime | None = None
    date_added: datetime | None = None
    manager: str | None = None
    node_name: str | None = None
    operating_system: OperatingSystem = Field(default_factory=OperatingSystem)


class DuplicateAgent(ApiModel):
    id: str
    name: str
    status: str | None = None
    groups: list[str] = Field(default_factory=list)
    last_keep_alive: datetime | None = None


class AgentLookup(ApiModel):
    query_name: str
    registered: bool
    duplicate_count: int
    agent: Agent | None
    duplicates: list[DuplicateAgent] | None = None
    data_as_of: datetime
    stale: bool


class AgentList(ApiModel):
    items: list[Agent]
    total: int
    limit: int
    offset: int
    data_as_of: datetime
    stale: bool
