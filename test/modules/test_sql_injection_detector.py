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

        sqli_message = '''http://test-apache-with-sql-injection-postgres:80/sql_injection.php?deleted='"&delete_widget='"&desc='"&description='"&destination='"&dir='"&direction='"&directory='"&disabled='"&dismiss='"&dl='"&do='"&domain='"&down='"&download='"&drop='"&dump='"&e='"&edit='"&email='"&enable='"&enabled='"&end='"&end_date='"&error='"&event='"&excerpt='"&export='"&f='"&features='"&fid='"&field='"&field_id='"&fields='"&file='"&file_name='"&filename='"&files='"&filter='"&firstname='"&first_name='"&flag='"&fname='"&folder='"&foo='"&form='"&format='"&from='"&function='"&g='"&gid='"&gmt_offset='"&go='"&group='"&group_id='"&groups='"&h='"&hash='"&height='"&hidden='"&history='"&host='"&hostname='"&html='"&i='"&id='"&ID='"&id_base='"&ids='"&image='"&img='"&import='"&index='"'''
        time_base_sqli_message = "http://test-apache-with-sql-injection-postgres:80/sql_injection.php?deleted='||pg_sleep(5)||'&delete_widget='||pg_sleep(5)||'&desc='||pg_sleep(5)||'&description='||pg_sleep(5)||'&destination='||pg_sleep(5)||'&dir='||pg_sleep(5)||'&direction='||pg_sleep(5)||'&directory='||pg_sleep(5)||'&disabled='||pg_sleep(5)||'&dismiss='||pg_sleep(5)||'&dl='||pg_sleep(5)||'&do='||pg_sleep(5)||'&domain='||pg_sleep(5)||'&down='||pg_sleep(5)||'&download='||pg_sleep(5)||'&drop='||pg_sleep(5)||'&dump='||pg_sleep(5)||'&e='||pg_sleep(5)||'&edit='||pg_sleep(5)||'&email='||pg_sleep(5)||'&enable='||pg_sleep(5)||'&enabled='||pg_sleep(5)||'&end='||pg_sleep(5)||'&end_date='||pg_sleep(5)||'&error='||pg_sleep(5)||'&event='||pg_sleep(5)||'&excerpt='||pg_sleep(5)||'&export='||pg_sleep(5)||'&f='||pg_sleep(5)||'&features='||pg_sleep(5)||'&fid='||pg_sleep(5)||'&field='||pg_sleep(5)||'&field_id='||pg_sleep(5)||'&fields='||pg_sleep(5)||'&file='||pg_sleep(5)||'&file_name='||pg_sleep(5)||'&filename='||pg_sleep(5)||'&files='||pg_sleep(5)||'&filter='||pg_sleep(5)||'&firstname='||pg_sleep(5)||'&first_name='||pg_sleep(5)||'&flag='||pg_sleep(5)||'&fname='||pg_sleep(5)||'&folder='||pg_sleep(5)||'&foo='||pg_sleep(5)||'&form='||pg_sleep(5)||'&format='||pg_sleep(5)||'&from='||pg_sleep(5)||'&function='||pg_sleep(5)||'&g='||pg_sleep(5)||'&gid='||pg_sleep(5)||'&gmt_offset='||pg_sleep(5)||'&go='||pg_sleep(5)||'&group='||pg_sleep(5)||'&group_id='||pg_sleep(5)||'&groups='||pg_sleep(5)||'&h='||pg_sleep(5)||'&hash='||pg_sleep(5)||'&height='||pg_sleep(5)||'&hidden='||pg_sleep(5)||'&history='||pg_sleep(5)||'&host='||pg_sleep(5)||'&hostname='||pg_sleep(5)||'&html='||pg_sleep(5)||'&i='||pg_sleep(5)||'&id='||pg_sleep(5)||'&ID='||pg_sleep(5)||'&id_base='||pg_sleep(5)||'&ids='||pg_sleep(5)||'&image='||pg_sleep(5)||'&img='||pg_sleep(5)||'&import='||pg_sleep(5)||'&index='||pg_sleep(5)||': It appears that this URL is vulnerable to time-based SQL injection"
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

        sqli_message = '''http://test-apache-with-sql-injection-mysql:80/sql_injection.php?deleted='"&delete_widget='"&desc='"&description='"&destination='"&dir='"&direction='"&directory='"&disabled='"&dismiss='"&dl='"&do='"&domain='"&down='"&download='"&drop='"&dump='"&e='"&edit='"&email='"&enable='"&enabled='"&end='"&end_date='"&error='"&event='"&excerpt='"&export='"&f='"&features='"&fid='"&field='"&field_id='"&fields='"&file='"&file_name='"&filename='"&files='"&filter='"&firstname='"&first_name='"&flag='"&fname='"&folder='"&foo='"&form='"&format='"&from='"&function='"&g='"&gid='"&gmt_offset='"&go='"&group='"&group_id='"&groups='"&h='"&hash='"&height='"&hidden='"&history='"&host='"&hostname='"&html='"&i='"&id='"&ID='"&id_base='"&ids='"&image='"&img='"&import='"&index='"'''
        time_base_sqli_message = "http://test-apache-with-sql-injection-mysql:80/sql_injection.php?deleted='||sleep(5)||'&delete_widget='||sleep(5)||'&desc='||sleep(5)||'&description='||sleep(5)||'&destination='||sleep(5)||'&dir='||sleep(5)||'&direction='||sleep(5)||'&directory='||sleep(5)||'&disabled='||sleep(5)||'&dismiss='||sleep(5)||'&dl='||sleep(5)||'&do='||sleep(5)||'&domain='||sleep(5)||'&down='||sleep(5)||'&download='||sleep(5)||'&drop='||sleep(5)||'&dump='||sleep(5)||'&e='||sleep(5)||'&edit='||sleep(5)||'&email='||sleep(5)||'&enable='||sleep(5)||'&enabled='||sleep(5)||'&end='||sleep(5)||'&end_date='||sleep(5)||'&error='||sleep(5)||'&event='||sleep(5)||'&excerpt='||sleep(5)||'&export='||sleep(5)||'&f='||sleep(5)||'&features='||sleep(5)||'&fid='||sleep(5)||'&field='||sleep(5)||'&field_id='||sleep(5)||'&fields='||sleep(5)||'&file='||sleep(5)||'&file_name='||sleep(5)||'&filename='||sleep(5)||'&files='||sleep(5)||'&filter='||sleep(5)||'&firstname='||sleep(5)||'&first_name='||sleep(5)||'&flag='||sleep(5)||'&fname='||sleep(5)||'&folder='||sleep(5)||'&foo='||sleep(5)||'&form='||sleep(5)||'&format='||sleep(5)||'&from='||sleep(5)||'&function='||sleep(5)||'&g='||sleep(5)||'&gid='||sleep(5)||'&gmt_offset='||sleep(5)||'&go='||sleep(5)||'&group='||sleep(5)||'&group_id='||sleep(5)||'&groups='||sleep(5)||'&h='||sleep(5)||'&hash='||sleep(5)||'&height='||sleep(5)||'&hidden='||sleep(5)||'&history='||sleep(5)||'&host='||sleep(5)||'&hostname='||sleep(5)||'&html='||sleep(5)||'&i='||sleep(5)||'&id='||sleep(5)||'&ID='||sleep(5)||'&id_base='||sleep(5)||'&ids='||sleep(5)||'&image='||sleep(5)||'&img='||sleep(5)||'&import='||sleep(5)||'&index='||sleep(5)||': It appears that this URL is vulnerable to time-based SQL injection"
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
