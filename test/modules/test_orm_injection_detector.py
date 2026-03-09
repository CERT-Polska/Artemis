# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.orm_injection_detector import OrmInjectionDetector


class OrmInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = OrmInjectionDetector

    def test_orm_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-flask-with-orm-injection-postgres", "port": 80},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue("ORM injection" in call.kwargs["status_reason"])
        results = call.kwargs["data"]["result"]
        self.assertTrue(len(results) >= 2, "Should detect both query param and header-based ORM injection")

        # Verify we catch both param and header injection types
        codes = [r.get("code") for r in results]
        self.assertIn("orm_injection", codes)
        self.assertIn("headers_orm_injection", codes)

        # Verify message field is present for each result
        for result in results:
            self.assertIn("message", result, "Each result should have a 'message' field")
            self.assertIn("url", result, "Each result should have a 'url' field")
            self.assertIn("code", result, "Each result should have a 'code' field")

    def test_contains_error(self) -> None:
        current_url = "http://test-flask-with-orm-injection-postgres:80/orm_injection?id=1"
        url_with_payload = "http://test-flask-with-orm-injection-postgres:80/orm_injection?id='"
        url_to_headers_vuln = "http://test-flask-with-orm-injection-postgres:80/headers_vuln"

        self.assertFalse(self.karton.contains_error(current_url, http_requests.get(current_url)))
        self.assertTrue(self.karton.contains_error(url_with_payload, http_requests.get(url_with_payload)))
        self.assertTrue(
            self.karton.contains_error(
                url_to_headers_vuln, http_requests.get(url_to_headers_vuln, headers={"User-Agent": "'"})
            )
        )

    def test_is_url_with_parameters(self) -> None:
        url_with_params = "http://test-flask-with-orm-injection-postgres:80/orm_injection?id=1"
        url_without_params = "http://test-flask-with-orm-injection-postgres:80/orm_injection"

        self.assertTrue(self.karton_class.is_url_with_parameters(url_with_params))
        self.assertFalse(self.karton_class.is_url_with_parameters(url_without_params))

