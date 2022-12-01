from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.port_scanner import PortScanner


class PortScannerTest(ArtemisModuleTestCase):
    karton_class = PortScanner

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.IP},
            payload={TaskType.IP: "192.168.3.14"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found potentially interesting ports: 23")
        self.assertEqual(call.kwargs["data"]["192.168.3.14"], {"23": {"service": "ftp", "ssl": False}})
