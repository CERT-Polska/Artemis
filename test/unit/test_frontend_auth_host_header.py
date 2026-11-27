import unittest

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from artemis import auth

SESSION_COOKIE = "artemis_session"


def build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/login")
    async def login() -> PlainTextResponse:
        return PlainTextResponse("login page")

    @app.get("/api/ping")
    async def api_ping() -> PlainTextResponse:
        return PlainTextResponse("pong")

    @app.get("/")
    async def root() -> PlainTextResponse:
        return PlainTextResponse("secret")

    @app.get("/add")
    async def add() -> PlainTextResponse:
        return PlainTextResponse("secret")

    app.add_middleware(auth.FrontendAuthMiddleware)
    app.add_middleware(SessionMiddleware, secret_key="test-secret", session_cookie=SESSION_COOKIE)
    return app


class FrontendAuthHostHeaderTest(unittest.TestCase):
    """The unprotected-path check must not be influenced by the client-controlled Host header.

    Starlette rebuilds request.url from the Host header, so a Host value containing a path could make
    request.url.path look like an unprotected path while the request is routed to a protected endpoint
    (GHSA-86qp-5c8j-p5mr).
    """

    SPOOFED_HOSTS = (
        "testserver/api/x?",
        "testserver/static/x?",
        "testserver/login?",
        "testserver/logout?",
        "testserver/api/x#",
    )

    def setUp(self) -> None:
        self.client = TestClient(build_app(), follow_redirects=False)

    def test_spoofed_host_does_not_bypass_authentication(self) -> None:
        for path in ("/", "/add"):
            for host in self.SPOOFED_HOSTS:
                with self.subTest(path=path, host=host):
                    response = self.client.get(path, headers={"Host": host})
                    self.assertEqual(response.status_code, 303)
                    self.assertEqual(response.headers["location"], "/login")

    def test_unprotected_paths_are_still_reachable_without_session(self) -> None:
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/api/ping").status_code, 200)

    def test_protected_path_still_requires_session(self) -> None:
        self.assertEqual(self.client.get("/add").status_code, 303)
