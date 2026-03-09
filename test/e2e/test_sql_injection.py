from test.e2e.base import BaseE2ETestCase


class SQLInjectionE2ETestCase(BaseE2ETestCase):
    def test_sql_injection_headers(self) -> None:
        tag = "sql-injection-headers-e2e"
        target = "test-apache-with-sql-injection-mysql"

        self.submit_tasks([target], tag=tag)
        self.wait_for_tasks_finished()

        self.assertMessagesContain(tag, "SQL Injection")
        self.assertMessagesContain(tag, "Headers used")
        self.assertMessagesContain(tag, "User-Agent")
