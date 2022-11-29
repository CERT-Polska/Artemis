from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.bruter import Bruter


class TestData(NamedTuple):
    host: str
    task_type: TaskType


class BruterTest(ArtemisModuleTestCase):
    karton_class = Bruter

    def test_simple(self) -> None:
        data = [
            TestData("test-service-with-bruteable-files", TaskType.SERVICE),
            TestData("192.168.3.4", TaskType.SERVICE),
        ]

        for entry in data:
            self.mock_db.reset_mock()
            task = Task(
                {"type": entry.task_type, "service": Service.HTTP},
                payload={"host": entry.host, "port": 80},
            )
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(call.kwargs["status_reason"], "Found files: .htaccess.bak, localhost.sql, sql.gz")
            self.assertEqual(call.kwargs["data"], [".htaccess.bak", "localhost.sql", "sql.gz"])
