import pytest

from app.services.bootstrap import compatibility, normalize_version, version_state


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("v4.14.6", "4.14.6"),
        ("Wazuh v4.14.6", "4.14.6"),
        ("Wazuh 4.14.6", "4.14.6"),
        ("4.14.6-1", "4.14.6"),
    ],
)
def test_normalize_version(raw: str, expected: str) -> None:
    assert normalize_version(raw) == expected


def test_invalid_version() -> None:
    with pytest.raises(ValueError):
        normalize_version("not-version")


def test_compatibility_and_states() -> None:
    assert compatibility("Wazuh v4.15.0", "4.14.6").compatible
    assert compatibility("4.14.6", "auto").target == "4.14.6"
    assert not compatibility("4.13.0", "4.14.6").compatible
    assert version_state("4.14.6", "4.14.6") == "current"
    assert version_state("4.13.0", "4.14.6") == "outdated"
    assert version_state("4.15.0", "4.14.6") == "newer_than_target"
    assert version_state(None, "4.14.6") == "unknown"
    assert version_state("bad", "4.14.6") == "unknown"
