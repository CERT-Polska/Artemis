from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.postman import Postman


class PostmanTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Postman  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.SMTP},
            payload={"host": "192.168.3.9", "port": 25},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found problems: possible to send e-mails without autorisation, the server is an open relay",
        )
        self.assertTrue(call.kwargs["data"].open_relay)
