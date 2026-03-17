import unittest
from unittest.mock import patch

from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

from artemis.api import verify_api_token
from artemis.config import Config

TEST_TOKEN = "test-secret-token"


def create_test_app() -> FastAPI:
    app = FastAPI()

    @app.get("/test", dependencies=[Depends(verify_api_token)])
    def test_endpoint() -> dict[str, str]:
        return {"status": "ok"}

    return app


class ApiTokenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_test_app()
        self.client = TestClient(self.app, raise_server_exceptions=False)

    def test_request_without_token_returns_error(self) -> None:
        """Requests without the X-API-Token header should not succeed."""
        with patch.object(Config.Miscellaneous, "API_TOKEN", TEST_TOKEN):
            response = self.client.get("/test")
        self.assertNotEqual(response.status_code, 200)

    def test_request_with_invalid_token_returns_401(self) -> None:
        """Requests with an incorrect API token should return HTTP 401."""
        with patch.object(Config.Miscellaneous, "API_TOKEN", TEST_TOKEN):
            response = self.client.get("/test", headers={"X-API-Token": "wrong-token"})
        self.assertEqual(response.status_code, 401)

    def test_request_with_valid_token_returns_200(self) -> None:
        """Requests with the correct API token should succeed."""
        with patch.object(Config.Miscellaneous, "API_TOKEN", TEST_TOKEN):
            response = self.client.get("/test", headers={"X-API-Token": TEST_TOKEN})
        self.assertEqual(response.status_code, 200)
