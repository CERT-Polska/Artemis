import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis import RedisError

from artemis.config import Config
from artemis.health import router


class HealthTest(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(router, prefix="/api")
        self.client = TestClient(app)
        self.client.headers["X-API-Token"] = "test-token"
        self.enterContext(patch.object(Config.Miscellaneous, "API_TOKEN", "test-token"))
        self.enterContext(patch.object(Config.Health, "HEALTH_DISK_PATH", "/"))
        self.enterContext(patch.object(Config.Health, "HEALTH_MIN_AVAILABLE_MEMORY_PERCENT", 20.0))
        self.enterContext(patch.object(Config.Health, "HEALTH_MIN_FREE_DISK_PERCENT", 20.0))
        self.enterContext(patch.object(Config.Health, "HEALTH_MAX_TASK_INACTIVITY_SECONDS", 14400))
        self.memory = self.enterContext(patch("artemis.health.psutil.virtual_memory"))
        self.disk = self.enterContext(patch("artemis.health.shutil.disk_usage"))
        self.redis = self.enterContext(patch("artemis.health.redis"))
        self.enterContext(patch("artemis.health.time.time", return_value=100000))
        self.memory.return_value = SimpleNamespace(total=100, available=50, free=0)
        self.disk.return_value = SimpleNamespace(total=100, free=50)
        self.enterContext(patch("artemis.health._backend", None))
        self.backend_class = self.enterContext(patch("artemis.health.KartonBackend"))
        self.backend = self.backend_class.return_value
        self.backend.get_binds.return_value = [SimpleNamespace(identity="nuclei")]
        self.backend.get_queue_names.return_value = ["karton.queue.normal:nuclei"]
        self.backend.redis.llen.return_value = 1
        self.redis.hget.return_value = b"100000"

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

    def test_configured_disk_path(self) -> None:
        with patch.object(Config.Health, "HEALTH_DISK_PATH", "/mnt/scan-data"):
            self.disk.return_value.free = 10
            response = self.client.get("/api/health")
        self.disk.assert_called_once_with("/mnt/scan-data")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Free space on /mnt/scan-data is 10.0%", response.json()["errors"]["disk"])

    def test_redis_failure_is_unhealthy(self) -> None:
        self.redis.hget.side_effect = RedisError("unavailable")
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["errors"]["worker"], "Unable to read task queues or consumption timestamps from Redis"
        )

    def test_idle_modules_are_healthy(self) -> None:
        for identities in [[], ["nuclei"]]:
            for timestamp in [None, b"0", b"invalid"]:
                with self.subTest(identities=identities, timestamp=timestamp):
                    self.backend.get_binds.return_value = [SimpleNamespace(identity=name) for name in identities]
                    self.backend.redis.llen.return_value = 0
                    self.redis.hget.return_value = timestamp
                    response = self.client.get("/api/health")
                    self.assertEqual(response.status_code, 200)
                    self.assertIsNone(response.json()["last_consumed_task_time"])
        self.redis.hget.assert_not_called()

    def test_queued_modules_without_recent_consumption_are_unhealthy(self) -> None:
        for stored_time, expected_time in [
            (None, None),
            (b"invalid", None),
            (b"nan", None),
            (b"inf", None),
            (b"-inf", None),
            (b"0", 0),
            (b"85599", 85599),
        ]:
            with self.subTest(stored_time=stored_time):
                self.redis.hget.return_value = stored_time
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["errors"], {"worker": "No tasks consumed in the last 4 hours"})
                self.assertEqual(response.json()["last_consumed_task_time"], expected_time)

    def test_consumption_at_inactivity_threshold_is_healthy(self) -> None:
        self.redis.hget.return_value = b"85600"
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_latest_queued_module_consumption_determines_worker_health(self) -> None:
        self.backend.get_binds.return_value = [SimpleNamespace(identity=name) for name in ["nuclei", "other"]]
        cases = [
            ([b"100000", None], 200, 100000),
            ([None, b"100000"], 200, 100000),
            ([b"100000", b"invalid"], 200, 100000),
            ([b"nan", b"100000"], 200, 100000),
            ([b"100000", b"0"], 200, 100000),
            ([b"0", b"100000"], 200, 100000),
            ([b"0", b"85599"], 503, 85599),
            ([None, b"invalid"], 503, None),
        ]
        for stored_times, status_code, expected_time in cases:
            with self.subTest(stored_times=stored_times):
                self.redis.hget.side_effect = stored_times
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, status_code)
                self.assertEqual(response.json()["last_consumed_task_time"], expected_time)
                if status_code == 503:
                    self.assertEqual(response.json()["errors"], {"worker": "No tasks consumed in the last 4 hours"})

    def test_idle_module_consumption_does_not_mask_stalled_queue(self) -> None:
        self.backend.get_binds.return_value = [SimpleNamespace(identity=name) for name in ["nuclei", "idle"]]
        self.backend.redis.llen.side_effect = [1, 0]
        self.redis.hget.side_effect = lambda key, identity: b"0" if identity == "nuclei" else b"100000"
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["errors"], {"worker": "No tasks consumed in the last 4 hours"})
        self.redis.hget.assert_called_once()

    def test_backend_is_reused_across_requests(self) -> None:
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.backend_class.assert_called_once()
        self.assertEqual(self.backend.get_binds.call_count, 2)

    def test_backend_initialization_failure_is_unhealthy_and_retried(self) -> None:
        self.backend_class.side_effect = RuntimeError("invalid S3 configuration")
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["errors"]["worker"], "Unable to initialize or access the Karton backend")
        self.backend_class.side_effect = None
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.backend_class.call_count, 2)

    def test_queue_read_failures_are_unhealthy(self) -> None:
        for operation in [self.backend.get_binds, self.backend.get_queue_names, self.backend.redis.llen]:
            with self.subTest(operation=operation):
                operation.side_effect = RedisError("unavailable")
                response = self.client.get("/api/health")
                self.assertEqual(response.status_code, 503)
                self.assertIn("Redis", response.json()["errors"]["worker"])
                operation.side_effect = None

    def test_all_failures_are_reported(self) -> None:
        self.memory.return_value.available = 10
        self.disk.return_value.free = 10
        self.redis.hget.return_value = b"0"
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(set(response.json()["errors"]), {"memory", "disk", "worker"})

    def test_missing_token_uses_standard_api_validation(self) -> None:
        self.client.headers.pop("X-API-Token")
        self.assertEqual(self.client.get("/api/health").status_code, 422)
        self.memory.assert_not_called()
        self.redis.hget.assert_not_called()

    def test_invalid_token_is_rejected(self) -> None:
        self.client.headers["X-API-Token"] = "wrong-token"
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid API token"})
        self.memory.assert_not_called()
        self.redis.hget.assert_not_called()

    def test_api_must_be_configured(self) -> None:
        with patch.object(Config.Miscellaneous, "API_TOKEN", None):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 401)
        self.assertIn("API_TOKEN", response.json()["detail"])
