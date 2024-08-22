# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
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

        self.assertTrue(self.karton_class.is_url_with_parameters(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_parameters(current_url))

    def test_are_request_efficient(self) -> None:
        current_url = "http://test-apache-with-sql-injection-postgres/sql_injection.php?id=1"
        url_with_sleep_payload = "http://test-apache-with-sql-injection-postgres/sql_injection.php?id='||pg_sleep(2)||'"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-postgres/headers_vuln.php"

        self.assertTrue(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, current_url))
        self.assertFalse(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, url_with_sleep_payload))
        self.assertFalse(
            self.karton_class.are_requests_time_efficient(
                SqlInjectionDetector, url_to_headers_vuln, headers={"User-Agent": "'||pg_sleep(2)||'"}
            )
        )

    def test_contains_error(self) -> None:
        current_url = "http://test-apache-with-sql-injection-postgres/sql_injection.php?id=2"
        url_with_payload = "http://test-apache-with-sql-injection-postgres/sql_injection.php?id='"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-postgres/headers_vuln.php"

        self.assertFalse(self.karton_class.contains_error(http_requests.get(current_url)))
        self.assertTrue(self.karton_class.contains_error(http_requests.get(url_with_payload)))
        self.assertTrue(
            self.karton_class.contains_error(http_requests.get(url_to_headers_vuln, headers={"User-Agent": "'"}))
        )


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

        self.assertTrue(self.karton_class.is_url_with_parameters(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_parameters(current_url))

    def test_are_request_efficient(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id=2"
        url_with_sleep_payload = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id='||sleep(2)||'"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-mysql/headers_vuln.php"

        self.assertTrue(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, current_url))
        self.assertFalse(self.karton_class.are_requests_time_efficient(SqlInjectionDetector, url_with_sleep_payload))
        self.assertFalse(
            self.karton_class.are_requests_time_efficient(
                SqlInjectionDetector, url_to_headers_vuln, headers={"User-Agent": "'||sleep(2)||'"}
            )
        )

    def test_contains_error(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id=1"
        url_with_payload = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id='"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-mysql/headers_vuln.php"

        self.assertFalse(self.karton_class.contains_error(http_requests.get(current_url)))
        self.assertTrue(self.karton_class.contains_error(http_requests.get(url_with_payload)))
        self.assertTrue(
            self.karton_class.contains_error(http_requests.get(url_to_headers_vuln, headers={"User-Agent": "'"}))
        )
