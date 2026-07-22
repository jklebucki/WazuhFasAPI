from datetime import UTC

from app.services.wazuh_data import to_agent, to_group


def test_agent_adapter_handles_upstream_variants() -> None:
    agent = to_agent(
        {
            "id": 7,
            "name": "HOST",
            "group": "one, two",
            "status_code": "3",
            "version": "invalid",
            "lastKeepAlive": "2026-01-01T10:00:00",
            "dateAdd": "not-a-date",
            "os": "invalid",
        },
        "4.14.6",
    )
    assert agent.id == "7"
    assert agent.groups == ["one", "two"]
    assert agent.status_code == 3
    assert agent.version is None
    assert agent.version_state == "unknown"
    assert agent.last_keep_alive and agent.last_keep_alive.tzinfo == UTC
    assert agent.date_added is None
    assert agent.operating_system.platform is None


def test_group_adapter_normalizes_names_and_optional_counts() -> None:
    assert to_group({"group": "default", "agent_count": "2"}).model_dump() == {
        "name": "default",
        "agent_count": 2,
    }
    assert to_group({"name": "empty", "agents": []}).agent_count is None
