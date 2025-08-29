from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.api_scanner import APIResult, APIScanner


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

        expected_results = [
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/user/' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
                endpoint="/api/user/' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
                method="GET",
                vulnerable=True,
                vuln_details="Endpoint might be vulnerable to SQli",
                status_code=500,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/user/' AND SLEEP(5) --",
                endpoint="/api/user/' AND SLEEP(5) --",
                method="GET",
                vulnerable=True,
                vuln_details="Endpoint might be vulnerable to SQli",
                status_code=500,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/ssti",
                endpoint="/api/ssti",
                method="GET",
                vulnerable=True,
                vuln_details="One or more parameter is vulnerable to XSS/HTML Injection Attack",
                status_code=200,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/ssti",
                endpoint="/api/ssti",
                method="GET",
                vulnerable=True,
                vuln_details="One or more parameter is vulnerable to SSTI Attack",
                status_code=200,
            ),
        ]

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(len(call.kwargs["data"]["results"]), len(expected_results))
        for i in range(len(expected_results)):
            self.assertEqual(
                call.kwargs["data"]["results"][i]["url"],
                expected_results[i].url,
            )
            self.assertEqual(
                call.kwargs["data"]["results"][i]["endpoint"],
                expected_results[i].endpoint,
            )
            self.assertEqual(call.kwargs["data"]["results"][i]["method"], expected_results[i].method)
            self.assertEqual(call.kwargs["data"]["results"][i]["vulnerable"], expected_results[i].vulnerable)
            self.assertEqual(call.kwargs["data"]["results"][i]["vuln_details"], expected_results[i].vuln_details)
            self.assertEqual(call.kwargs["data"]["results"][i]["status_code"], expected_results[i].status_code)
