from karton.core import Task
from artemis import http_requests
from test.base import ArtemisModuleTestCase
from artemis.binds import TaskStatus, TaskType, Service
from artemis.modules.sql_injection_detector import SqlInjectionDetector


class PostgresSqlInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = SqlInjectionDetector

    def test_sql_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test-apache-with-sql-injection-postgres"},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertGreater(len(call.kwargs["status_reason"]), 0)

    def test_is_url_with_payload(self) -> None:
        url_with_payload = "http://test-apache-with-sql-injection-postgres?id=3"
        current_url = "http://test-apache-with-sql-injection-postgres"

        self.assertTrue(self.karton_class.is_url_with_payload(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_payload(current_url))

    def test_are_request_efficient_False(self) -> None:
        current_url = ("http://test-apache-with-sql-injection-postgres")
        url_with_sleep_payload = "http://test-apache-with-sql-injection-postgres?id='||pg_sleep(1)||'"

        self.assertTrue(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, current_url))
        self.assertFalse(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, url_with_sleep_payload))

    def test_contains_error(self) -> None:
        url_with_payload = "http://test-apache-with-sql-injection-postgres?id='"
        current_url = "http://test-apache-with-sql-injection-postgres"

        self.assertTrue(self.karton_class.contains_error(http_requests.get(url_with_payload)))
        self.assertFalse(self.karton_class.contains_error(http_requests.get(current_url)))


class MysqlSqlInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = SqlInjectionDetector

    def test_sql_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test-apache-with-sql-injection-mysql"},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertGreater(len(call.kwargs["status_reason"]), 0)

    def test_is_url_with_payload(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql"
        url_with_payload = "http://test-apache-with-sql-injection-mysql?id=3"

        self.assertTrue(self.karton_class.is_url_with_payload(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_payload(current_url))

    def test_are_request_efficient_False(self) -> None:
        current_url = ("http://test-apache-with-sql-injection-mysql")
        url_with_sleep_payload = "http://test-apache-with-sql-injection-mysql?id='||sleep(1)||'"

        self.assertTrue(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, current_url))
        self.assertFalse(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, url_with_sleep_payload))

    def test_contains_error(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql"
        url_with_payload = "http://test-apache-with-sql-injection-mysql?id='"

        self.assertFalse(self.karton_class.contains_error(http_requests.get(current_url)))
        self.assertTrue(self.karton_class.contains_error(http_requests.get(url_with_payload)))

