"""Group response models."""

from datetime import datetime

from app.models.agent import Agent
from app.models.common import ApiModel


class Group(ApiModel):
    name: str
    agent_count: int | None = None


class GroupList(ApiModel):
    items: list[Group]
    total: int
    data_as_of: datetime
    stale: bool


class GroupDetail(ApiModel):
    group: Group
    agents: list[Agent]
    total: int
    data_as_of: datetime
    stale: bool
