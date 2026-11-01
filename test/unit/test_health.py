import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from artemis.health import router


class HealthTest(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_resource_thresholds(self) -> None:
        cases = [
            (50, 50, 200, {"status": "ok"}),
            (20, 20, 200, {"status": "ok"}),
            (19, 50, 503, {"error": "Available RAM is below 20%"}),
            (50, 19, 503, {"error": "Free disk space is below 20%"}),
            (19, 19, 503, {"error": "Available RAM is below 20%; Free disk space is below 20%"}),
            (0, 0, 503, {"error": "Available RAM is below 20%; Free disk space is below 20%"}),
        ]
        for available_memory, free_disk, status_code, body in cases:
            with self.subTest(available_memory=available_memory, free_disk=free_disk):
                with (
                    patch("artemis.health.psutil.virtual_memory") as memory,
                    patch("artemis.health.shutil.disk_usage") as disk,
                ):
                    # Available RAM includes reclaimable cache, unlike strictly free RAM.
                    memory.return_value = SimpleNamespace(total=100, available=available_memory, free=0)
                    disk.return_value = SimpleNamespace(total=100, free=free_disk)

                    response = self.client.get("/health")

                    self.assertEqual(response.status_code, status_code)
                    self.assertEqual(response.json(), body)
                    disk.assert_called_once_with("/")
