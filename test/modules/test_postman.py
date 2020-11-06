from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.postman import Postman


class PostmanTest(ArtemisModuleTestCase):
    karton_class = Postman

    def test_simple(self) -> None:
        task = Task(
            {"service": Service.SMTP},
            payload={TaskType.IP: "192.168.3.9", "port": 25},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found problems: the server is an open relay")
        self.assertTrue(call.kwargs["data"].open_relay)
