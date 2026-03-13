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
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-sql-injection-postgres", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        sqli_message = "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id='\""
        time_base_sqli_message = (
            "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id='||pg_sleep(5)||'"
            ": It appears that this URL is vulnerable to time-based SQL injection"
        )
        sqli_by_headers_message = (
            "http://test-apache-with-sql-injection-postgres:80/headers_vuln.php: "
            "It appears that this URL is vulnerable to SQL injection through HTTP Headers"
        )
        time_base_sqli_by_headers_message = (
            "http://test-apache-with-sql-injection-postgres:80/headers_vuln.php: "
            "It appears that this URL is vulnerable to time-based SQL injection through HTTP Headers"
        )
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(sqli_message in call.kwargs["status_reason"])
        self.assertTrue(time_base_sqli_message in call.kwargs["status_reason"])
        self.assertTrue(sqli_by_headers_message in call.kwargs["status_reason"])
        self.assertTrue(time_base_sqli_by_headers_message in call.kwargs["status_reason"])
        self.assertEqual(len(call.kwargs["data"]["result"]), 4)

    def test_is_url_with_parameters(self) -> None:
        url_with_payload = "http://test-apache-with-sql-injection-postgres:80?id=3"
        current_url = "http://test-apache-with-sql-injection-postgres:80"

        self.assertTrue(self.karton_class.is_url_with_parameters(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_parameters(current_url))

    def test_measure_request_time(self) -> None:
        current_url = "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id=1"
        url_with_sleep_payload = (
            "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id='||pg_sleep(5)||'"
        )
        url_to_headers_vuln = "http://test-apache-with-sql-injection-postgres:80/headers_vuln.php"

        self.assertTrue(self.karton.measure_request_time(current_url) < 1)
        self.assertTrue(self.karton.measure_request_time(url_with_sleep_payload) >= 5)
        self.assertTrue(
            self.karton.measure_request_time(url_to_headers_vuln, headers={"User-Agent": "'||pg_sleep(5)||'"}) >= 5
        )

    def test_contains_error(self) -> None:
        current_url = "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id=5"
        url_with_payload = "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?id='"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-postgres:80/headers_vuln.php"

        self.assertFalse(self.karton.contains_error(current_url, http_requests.get(current_url)))
        self.assertTrue(self.karton.contains_error(url_with_payload, http_requests.get(url_with_payload)))
        self.assertTrue(
            self.karton.contains_error(
                url_to_headers_vuln, http_requests.get(url_to_headers_vuln, headers={"User-Agent": "'"})
            )
        )


class MysqlSqlInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = SqlInjectionDetector

    def test_sql_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-sql-injection-mysql", "port": 80},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        sqli_message = "http://test-apache-with-sql-injection-mysql:80/sql_injection.php?id='\""
        time_base_sqli_message = (
            "http://test-apache-with-sql-injection-mysql:80/sql_injection.php?id='||sleep(5)||'"
            ": It appears that this URL is vulnerable to time-based SQL injection"
        )
        sqli_by_headers_message = (
            "http://test-apache-with-sql-injection-mysql:80/headers_vuln.php: "
            "It appears that this URL is vulnerable to SQL injection through HTTP Headers"
        )
        time_base_sqli_by_headers_message = (
            "http://test-apache-with-sql-injection-mysql:80/headers_vuln.php: "
            "It appears that this URL is vulnerable to time-based SQL injection "
            "through HTTP Headers"
        )

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(sqli_message in call.kwargs["status_reason"])
        self.assertTrue(time_base_sqli_message in call.kwargs["status_reason"])
        self.assertTrue(sqli_by_headers_message in call.kwargs["status_reason"])
        self.assertTrue(time_base_sqli_by_headers_message in call.kwargs["status_reason"])
        self.assertEqual(len(call.kwargs["data"]["result"]), 4)

    def test_is_url_with_parameters(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql"
        url_with_payload = "http://test-apache-with-sql-injection-mysql?id=3"

        self.assertTrue(self.karton_class.is_url_with_parameters(url_with_payload))
        self.assertFalse(self.karton_class.is_url_with_parameters(current_url))

    def test_measure_request_time(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id=5"
        url_with_sleep_payload = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id='||sleep(5)||'"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-mysql/headers_vuln.php"

        self.assertTrue(self.karton.measure_request_time(current_url) < 1)
        self.assertTrue(self.karton.measure_request_time(url_with_sleep_payload) >= 5)
        self.assertTrue(
            self.karton.measure_request_time(url_to_headers_vuln, headers={"User-Agent": "'||sleep(5)||'"}) >= 5
        )

    def test_contains_error(self) -> None:
        current_url = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id=1"
        url_with_payload = "http://test-apache-with-sql-injection-mysql/sql_injection.php?id='"
        url_to_headers_vuln = "http://test-apache-with-sql-injection-mysql/headers_vuln.php"

        self.assertFalse(self.karton.contains_error(current_url, http_requests.get(current_url)))
        self.assertTrue(self.karton.contains_error(url_with_payload, http_requests.get(url_with_payload)))
        self.assertTrue(
            self.karton.contains_error(
                url_to_headers_vuln, http_requests.get(url_to_headers_vuln, headers={"User-Agent": "'"})
            )
        )
