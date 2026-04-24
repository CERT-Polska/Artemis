"""Integration tests for frontend session authentication.

Tests that frontend routes redirect unauthenticated users to /login and that
valid credentials grant access through a session cookie.
"""

from test.e2e.base import (
    BACKEND_URL,
    FRONTEND_PASSWORD,
    FRONTEND_USERNAME,
    BaseE2ETestCase,
)

import requests


class FrontendAuthenticationTestCase(BaseE2ETestCase):
    """Test that frontend routes properly enforce session authentication."""

    def test_unauthenticated_get_redirects_to_login(self) -> None:
        response = requests.get(BACKEND_URL, allow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["location"].endswith("/login"))

    def test_login_with_valid_credentials_sets_session(self) -> None:
        with requests.Session() as s:
            response = s.post(
                BACKEND_URL + "login",
                data={"username": FRONTEND_USERNAME, "password": FRONTEND_PASSWORD},
                allow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)

            response = s.get(BACKEND_URL)
            self.assertEqual(response.status_code, 200)

    def test_login_with_invalid_password_returns_401(self) -> None:
        response = requests.post(
            BACKEND_URL + "login",
            data={"username": FRONTEND_USERNAME, "password": "wrong"},
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_login_with_unknown_username_returns_401(self) -> None:
        response = requests.post(
            BACKEND_URL + "login",
            data={"username": "nobody", "password": FRONTEND_PASSWORD},
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_logout_clears_session(self) -> None:
        with requests.Session() as s:
            s.post(BACKEND_URL + "login", data={"username": FRONTEND_USERNAME, "password": FRONTEND_PASSWORD})
            s.post(BACKEND_URL + "logout")

            response = s.get(BACKEND_URL, allow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertTrue(response.headers["location"].endswith("/login"))

    def test_static_assets_are_public(self) -> None:
        # The login page must be able to load its own CSS, so /static/* bypasses
        # the session check.
        response = requests.get(BACKEND_URL + "static/style.css")
        self.assertEqual(response.status_code, 200)

    def test_api_endpoints_return_401_not_redirect(self) -> None:
        response = requests.get(
            BACKEND_URL + "api/analyses",
            headers={"X-API-Token": "wrong"},
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)
