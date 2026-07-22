from unittest.mock import patch

from app.core.security import api_key_matches


def test_api_key_matching() -> None:
    assert api_key_matches("secret", "secret")
    assert not api_key_matches(None, "secret")
    assert not api_key_matches("wrong", "secret")


def test_compare_digest_is_used() -> None:
    with patch("app.core.security.secrets.compare_digest", return_value=True) as compare:
        assert api_key_matches("one", "two")
        compare.assert_called_once_with(b"one", b"two")
