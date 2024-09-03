import requests
from karton.core import Task

from artemis.binds import TaskType, Service
from artemis.modules.dalfox import DalFox
from test.base import ArtemisModuleTestCase


class DalFoxTestCase(ArtemisModuleTestCase):
    karton_class = DalFox

    def test_dalfox_run(self):
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-sql-injection-xss"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], "INTERESTING")

    def test_dalfox_param_name_with_xss(self):
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-sql-injection-xss/xss.php"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertTrue(call.kwargs["data"]["result"][0]["param"] == "username")
        self.assertTrue(False)

    def test_dalfox_data_result_without_xss_error(self):
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-sql-injection-xss/broken.php"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertTrue(call.kwargs["data"]["result"] == [])
        self.assertTrue(False)
