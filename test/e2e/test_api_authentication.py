"""Integration tests for API authentication.

Tests that API endpoints properly reject requests with invalid API tokens.
"""

from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import Any, Dict, List, Optional, Tuple

import requests

API_TOKEN = "api-token"
VALID_HEADERS: Dict[str, str] = {"X-API-Token": API_TOKEN}


class ApiAuthenticationTestCase(BaseE2ETestCase):
    """Test that API endpoints properly enforce authentication."""

    def test_invalid_api_token_returns_401(self) -> None:
        """Test that requests with invalid API token are rejected with 401."""
        invalid_headers: Dict[str, str] = {"X-API-Token": "wrong-token"}

        endpoints: List[Tuple[str, str, Optional[Dict[str, Any]]]] = [
            ("GET", "api/analyses", None),
            ("GET", "api/num-queued-tasks", None),
            ("GET", "api/task-results", None),
            ("GET", "api/exports", None),
            ("POST", "api/add", {"targets": ["example.com"]}),
        ]

        for method, path, json_data in endpoints:
            response = requests.request(
                method,
                BACKEND_URL + path,
                json=json_data,
                headers=invalid_headers,
            )
            self.assertEqual(
                response.status_code,
                401,
                f"{method} /{path} should return 401 with invalid token, got {response.status_code}",
            )
