import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis import RedisError

from artemis.config import Config
from artemis.health import router
from artemis.task_utils import LAST_CONSUMED_TASK_TIME_KEY


class HealthTest(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(router, prefix="/api")
        self.client = TestClient(app)
        self.client.headers["X-API-Token"] = "test-token"
        self.enterContext(patch.object(Config.Miscellaneous, "API_TOKEN", "test-token"))
        self.enterContext(patch.object(Config.Health, "HEALTH_MIN_AVAILABLE_MEMORY_PERCENT", 20.0))
        self.enterContext(patch.object(Config.Health, "HEALTH_MIN_FREE_DISK_PERCENT", 20.0))
        self.enterContext(patch.object(Config.Health, "HEALTH_MAX_TASK_INACTIVITY_SECONDS", 14400))
        self.memory = self.enterContext(patch("artemis.health.psutil.virtual_memory"))
        self.disk = self.enterContext(patch("artemis.health.shutil.disk_usage"))
        self.redis = self.enterContext(patch("artemis.health.redis"))
        self.enterContext(patch("artemis.health.time.time", return_value=100000))
        self.memory.return_value = SimpleNamespace(total=100, available=50, free=0)
        self.disk.return_value = SimpleNamespace(total=100, free=50)
        self.redis.get.return_value = b"100000"

    def test_resource_thresholds(self) -> None:
        cases = [
            (50, 50, []),
            (20, 20, []),
            (19.99, 20, ["memory"]),
            (20, 19.99, ["disk"]),
            (19, 50, ["memory"]),
            (50, 19, ["disk"]),
            (19, 19, ["memory", "disk"]),
            (0, 0, ["memory", "disk"]),
        ]
        for available_memory, free_disk, error_keys in cases:
            with self.subTest(available_memory=available_memory, free_disk=free_disk):
                # Available RAM includes reclaimable cache, unlike strictly free RAM.
                self.memory.return_value.available = available_memory
                self.disk.return_value.free = free_disk
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, 503 if error_keys else 200)
                self.assertEqual(set(response.json().get("errors", {})), set(error_keys))
                self.assertEqual(response.json()["last_consumed_task_time"], 100000)
                for error in response.json().get("errors", {}).values():
                    self.assertIn("at least 20% is required", error)
        self.disk.assert_called_with("/")

    def test_task_inactivity_threshold(self) -> None:
        for age, expected_status in [
            (0, 200),
            (Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS, 200),
            (Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS + 1, 503),
        ]:
            with self.subTest(age=age):
                timestamp = 100000 - age
                self.redis.get.return_value = str(timestamp).encode()
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(response.json()["last_consumed_task_time"], timestamp)
                if expected_status == 503:
                    self.assertEqual(
                        response.json()["errors"]["worker"], "No task has been consumed in the last 4 hours"
                    )
        self.redis.get.assert_called_with(LAST_CONSUMED_TASK_TIME_KEY)

    def test_configured_resource_thresholds(self) -> None:
        with (
            patch.object(Config.Health, "HEALTH_MIN_AVAILABLE_MEMORY_PERCENT", 60.5),
            patch.object(Config.Health, "HEALTH_MIN_FREE_DISK_PERCENT", 10.5),
        ):
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(set(response.json()["errors"]), {"memory"})
            self.assertIn("at least 60.5% is required", response.json()["errors"]["memory"])
            self.memory.return_value.available = 60.5
            self.disk.return_value.free = 10.5
            self.assertEqual(self.client.get("/api/health").status_code, 200)
            self.disk.return_value.free = 10.49
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(set(response.json()["errors"]), {"disk"})
            self.assertIn("at least 10.5% is required", response.json()["errors"]["disk"])

    def test_configured_task_inactivity_threshold(self) -> None:
        with patch.object(Config.Health, "HEALTH_MAX_TASK_INACTIVITY_SECONDS", 1800):
            self.redis.get.return_value = b"98200"
            self.assertEqual(self.client.get("/api/health").status_code, 200)
            self.redis.get.return_value = b"98199"
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["errors"]["worker"], "No task has been consumed in the last 0.5 hours")

    def test_missing_or_invalid_timestamp_is_unhealthy(self) -> None:
        for timestamp in [None, b"invalid", b"nan", b"inf"]:
            with self.subTest(timestamp=timestamp):
                self.redis.get.return_value = timestamp
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, 503)
                self.assertIsNone(response.json()["last_consumed_task_time"])
                self.assertIn("worker", response.json()["errors"])

    def test_redis_failure_is_unhealthy(self) -> None:
        self.redis.get.side_effect = RedisError("unavailable")
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["errors"]["worker"], "Unable to read last_consumed_task_time from Redis")

    def test_all_failures_are_reported(self) -> None:
        self.memory.return_value.available = 10
        self.disk.return_value.free = 10
        self.redis.get.return_value = b"0"
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(set(response.json()["errors"]), {"memory", "disk", "worker"})

    def test_missing_token_uses_standard_api_validation(self) -> None:
        self.client.headers.pop("X-API-Token")
        self.assertEqual(self.client.get("/api/health").status_code, 422)
        self.memory.assert_not_called()
        self.redis.get.assert_not_called()

    def test_invalid_token_is_rejected(self) -> None:
        self.client.headers["X-API-Token"] = "wrong-token"
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid API token"})
        self.memory.assert_not_called()
        self.redis.get.assert_not_called()

    def test_api_must_be_configured(self) -> None:
        with patch.object(Config.Miscellaneous, "API_TOKEN", None):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 401)
        self.assertIn("API_TOKEN", response.json()["detail"])
