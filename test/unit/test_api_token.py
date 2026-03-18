import sys
import unittest
from unittest.mock import MagicMock, patch

# The artemis.api module imports artemis.producer, which initializes a global Producer instance.
# This instance attempts to connect to Redis on import. During unit tests, Redis might not be available
# at the expected 'redis' hostname (it's 'test-redis' in docker-compose.test.yaml), causing
# ImportError. To avoid this, we mock artemis.producer before importing artemis.api.
sys.modules["artemis.producer"] = MagicMock()

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from artemis.api import verify_api_token  # noqa: E402
from artemis.config import Config  # noqa: E402

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
