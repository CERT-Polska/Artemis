from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.vcs import VCSScanner


class TestData(NamedTuple):
    host: str
    port: int
    ssl: bool
    task_type: TaskType


class VCSTest(ArtemisModuleTestCase):
    karton_class = VCSScanner

    def test_robots(self) -> None:
        data = [
            TestData("test-service-with-exposed-git", 80, False, TaskType.SERVICE),
            TestData("192.168.3.11", 80, False, TaskType.SERVICE),
        ]

        for entry in data:
            self.mock_db.reset_mock()
            task = Task(
                {"type": entry.task_type, "service": Service.HTTP},
                payload={
                    "host": entry.host,
                    "port": entry.port,
                    "ssl": entry.ssl,
                },
            )
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(call.kwargs["status_reason"], "Found version control system data: git")
            self.assertEqual(call.kwargs["data"], {"git": True, "svn": False, "hg": False})
