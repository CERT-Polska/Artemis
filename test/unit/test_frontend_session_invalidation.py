import unittest

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from artemis import auth

SESSION_COOKIE = "artemis_session"


def build_app() -> FastAPI:
    app = FastAPI()

    @app.post("/login")
    async def login(request: Request) -> PlainTextResponse:
        auth.create_session(request)
        return PlainTextResponse("logged in")

    @app.post("/logout")
    async def logout(request: Request) -> PlainTextResponse:
        auth.destroy_session(request)
        return PlainTextResponse("logged out")

    @app.get("/protected")
    async def protected() -> PlainTextResponse:
        return PlainTextResponse("secret")

    app.add_middleware(auth.FrontendAuthMiddleware)
    app.add_middleware(SessionMiddleware, secret_key="test-secret", session_cookie=SESSION_COOKIE)
    return app


class FrontendSessionInvalidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(build_app(), follow_redirects=False)

    def tearDown(self) -> None:
        for key in auth._redis.keys(auth.SESSION_REDIS_KEY_PREFIX + "*"):
            auth._redis.delete(key)

    def test_unauthenticated_request_is_redirected(self) -> None:
        self.assertEqual(self.client.get("/protected").status_code, 303)

    def test_login_grants_access(self) -> None:
        self.client.post("/login")
        self.assertEqual(self.client.get("/protected").status_code, 200)

    def test_stolen_cookie_is_rejected_after_logout(self) -> None:
        self.client.post("/login")
        stolen_cookie = self.client.cookies[SESSION_COOKIE]

        self.client.post("/logout")

        # The attacker presents the cookie that has been copied before the user logged out
        attacker = TestClient(build_app(), follow_redirects=False)
        attacker.cookies.set(SESSION_COOKIE, stolen_cookie)
        self.assertEqual(attacker.get("/protected").status_code, 303)

    def test_cookie_is_rejected_when_session_is_not_stored_on_server(self) -> None:
        self.client.post("/login")
        for key in auth._redis.keys(auth.SESSION_REDIS_KEY_PREFIX + "*"):
            auth._redis.delete(key)

        self.assertEqual(self.client.get("/protected").status_code, 303)

    def test_logout_does_not_affect_other_sessions(self) -> None:
        other_client = TestClient(build_app(), follow_redirects=False)
        other_client.post("/login")
        self.client.post("/login")

        self.client.post("/logout")

        self.assertEqual(other_client.get("/protected").status_code, 200)

    def test_session_expiration_is_refreshed(self) -> None:
        self.client.post("/login")
        (key,) = auth._redis.keys(auth.SESSION_REDIS_KEY_PREFIX + "*")
        auth._redis.expire(key, 60)

        self.client.get("/protected")

        self.assertGreater(auth._redis.ttl(key), 60)
