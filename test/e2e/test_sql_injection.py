import socket
from test.e2e.base import BaseE2ETestCase


class SQLInjectionE2ETestCase(BaseE2ETestCase):
    def test_sql_injection_headers(self) -> None:
        tag = "sql-injection-headers-e2e"
        target = socket.gethostbyname("test-apache-with-sql-injection-mysql")

        self.submit_tasks([target], tag=tag)
        self.wait_for_tasks_finished()

        messages = self.get_task_messages(tag)
        self.assertTrue(any("SQL injection through HTTP Headers" in m for m in messages))
        self.assertTrue(any("Headers used" in m for m in messages))
        self.assertTrue(any("User-Agent" in m for m in messages))
