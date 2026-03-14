import hmac
from unittest.mock import patch

import pytest

from artemis.api import verify_api_token


@pytest.fixture(autouse=True)
def set_api_token():
    with patch("artemis.api.Config.Miscellaneous.API_TOKEN", "test-secret-token"):
        yield


def test_valid_token_passes():
    verify_api_token("test-secret-token")


def test_invalid_token_raises_401():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        verify_api_token("wrong-token")
    assert exc_info.value.status_code == 401


def test_empty_token_raises_401():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        verify_api_token("")
    assert exc_info.value.status_code == 401


def test_no_api_token_configured_raises_401():
    from fastapi import HTTPException

    with patch("artemis.api.Config.Miscellaneous.API_TOKEN", ""):
        with pytest.raises(HTTPException) as exc_info:
            verify_api_token("any-token")
        assert exc_info.value.status_code == 401


def test_uses_constant_time_comparison():
    with patch("artemis.api.hmac.compare_digest", wraps=hmac.compare_digest) as mock_compare:
        verify_api_token("test-secret-token")
        mock_compare.assert_called_once_with("test-secret-token", "test-secret-token")
