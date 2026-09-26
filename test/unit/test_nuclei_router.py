import unittest
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei_router import (
    NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY,
    NUCLEI_ROUTER_SCAN_MODE_KEY,
    NucleiRouter,
    NucleiScanMode,
)


class TestNucleiRouter(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with patch("artemis.resource_lock.REDIS") as mock_redis:
            mock_redis.set.return_value = True
            cls.router = NucleiRouter(config=MagicMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def test_routing_http_service(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "example.com", "port": 80, "ssl": False},
        )
        self.router.add_task = MagicMock()  # type: ignore[method-assign]
        self.router.save_task_result = MagicMock()  # type: ignore[method-assign]

        with patch.object(self.router, "get_nuclei_additional_flags_for_task", return_value=[]):
            self.router.run(task)

        self.router.add_task.assert_called_once()
        _, routed_task = self.router.add_task.call_args[0]
        self.assertEqual(routed_task.headers["type"], TaskType.NUCLEI_TARGET)
        self.assertEqual(routed_task.payload["host"], "example.com")
        self.assertEqual(routed_task.payload["port"], 80)
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_SCAN_MODE_KEY], NucleiScanMode.HTTP.value)

        self.router.save_task_result.assert_called_once()
        save_call = self.router.save_task_result.call_args[1]
        self.assertEqual(save_call["status"], TaskStatus.OK)
        self.assertEqual(save_call["data"]["nuclei_scan_mode"], NucleiScanMode.HTTP.value)
        self.assertEqual(save_call["data"]["url"], "http://example.com:80")

    def test_routing_non_http_service(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.REDIS.value},
            payload={"host": "192.168.1.100", "port": 6379, "ssl": False},
        )
        self.router.add_task = MagicMock()  # type: ignore[method-assign]
        self.router.save_task_result = MagicMock()  # type: ignore[method-assign]

        self.router.run(task)

        self.router.add_task.assert_called_once()
        _, routed_task = self.router.add_task.call_args[0]
        self.assertEqual(routed_task.headers["type"], TaskType.NUCLEI_TARGET)
        self.assertEqual(routed_task.payload["host"], "192.168.1.100")
        self.assertEqual(routed_task.payload["port"], 6379)
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_SCAN_MODE_KEY], NucleiScanMode.OTHER.value)
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY], [])

        self.router.save_task_result.assert_called_once()
        save_call = self.router.save_task_result.call_args[1]
        self.assertEqual(save_call["status"], TaskStatus.OK)
        self.assertEqual(save_call["data"]["nuclei_scan_mode"], NucleiScanMode.OTHER.value)
        self.assertNotIn("url", save_call["data"])
