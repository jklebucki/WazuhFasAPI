"""Version and bootstrap manifest rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from packaging.version import InvalidVersion, Version

_VERSION_RE = re.compile(r"(?i)(?:wazuh\s*)?v?(\d+(?:\.\d+){1,3})(?:-\d+)?")


def normalize_version(value: str) -> str:
    match = _VERSION_RE.search(value.strip())
    if not match:
        raise ValueError("invalid Wazuh version")
    text = match.group(1)
    try:
        return str(Version(text))
    except InvalidVersion as exc:
        raise ValueError("invalid Wazuh version") from exc


def version_state(
    agent_version: str | None, target_version: str
) -> Literal["current", "outdated", "newer_than_target", "unknown"]:
    if not agent_version:
        return "unknown"
    try:
        agent = Version(normalize_version(agent_version))
        target = Version(normalize_version(target_version))
    except ValueError:
        return "unknown"
    if agent == target:
        return "current"
    return "outdated" if agent < target else "newer_than_target"


@dataclass(frozen=True, slots=True)
class VersionCompatibility:
    manager: str
    target: str
    compatible: bool


def compatibility(manager_raw: str, target_raw: str) -> VersionCompatibility:
    manager = normalize_version(manager_raw)
    target = manager if target_raw == "auto" else normalize_version(target_raw)
    return VersionCompatibility(manager, target, Version(manager) >= Version(target))
