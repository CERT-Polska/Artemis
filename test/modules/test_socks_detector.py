from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.socks_detector import SocksDetector


class SocksDetectorTest(ArtemisModuleTestCase):
    karton_class = SocksDetector  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "SOCKS5 proxy on test-socks-open-proxy:1080 allows unauthenticated connections.",
        )
        self.assertEqual(call.kwargs["data"].socks_version, 5)
