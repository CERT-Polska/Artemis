from karton.core import Task

from artemis.binds import TaskType, Service
from artemis.modules.dalfox import DalFox
from test.base import ArtemisModuleTestCase


class DalFoxTestCase(ArtemisModuleTestCase):
    karton_class = DalFox

    def test_dalfox(self):
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test-apache-with-sql-injection-xss"},
        )
        # self.run_task(task)
        # (call,) = self.mock_db.save_task_result.call_args_list
        #
        # print(call.kwargs["status"])
        self.assertTrue(False)
