from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.api_scanner import APIScanner


class APIScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = APIScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-flask-vulnerable-api",
                "port": 5000,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-flask-vulnerable-api:5000/api/user/' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)")
        self.assertEqual(call.kwargs["data"]["results"][0]["method"], "GET")
        self.assertEqual(call.kwargs["data"]["results"][0]["vulnerable"], True)
        self.assertEqual(call.kwargs["data"]["results"][0]["vuln_details"], "Endpoint might be vulnerable to SQli")
        self.assertEqual(call.kwargs["data"]["results"][0]["status_code"], 500)
