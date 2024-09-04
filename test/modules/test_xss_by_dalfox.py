# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.dalfox import DalFox


class DalFoxTestCase(ArtemisModuleTestCase):
    karton_class = DalFox

    def test_dalfox_run_on_index_page(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-sql-injection-xss"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertTrue(len(call.kwargs["data"]["result"]) >= 1)
        self.assertTrue(call.kwargs["task"].payload["url"] == "http://test_apache-with-sql-injection-xss")
        self.assertTrue(call.kwargs["data"]["result"][0]["url"].startswith("http://test_apache-with-sql-injection-xss/xss.php?username="))

    def test_dalfox_on_xss_page(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-sql-injection-xss/xss.php"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertTrue(call.kwargs["data"]["result"][0]["param"] == "username")
        self.assertTrue(call.kwargs["data"]["result"][0]["evidence"].startswith("14 line:"))
        self.assertTrue(call.kwargs["task"].payload["url"] == "http://test_apache-with-sql-injection-xss/xss.php")
        self.assertTrue(call.kwargs["data"]["result"][0]["url"].startswith("http://test_apache-with-sql-injection-xss/xss.php?username="))
