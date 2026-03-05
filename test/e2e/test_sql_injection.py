from test.e2e.base import BaseE2ETestCase


class SQLInjectionE2ETestCase(BaseE2ETestCase):
    def test_sql_injection_headers(self) -> None:
        tag = "sql-injection-headers-e2e"
        target = "test-apache-with-sql-injection-mysql"

        self.submit_tasks([target], tag=tag)
        self.wait_for_tasks_finished()

        self.assertMessagesContain(tag, "SQL injection through HTTP Headers")
        self.assertMessagesContain(tag, "Headers used")
        self.assertMessagesContain(tag, "User-Agent")

        task_results = self.get_task_results()

        found_headers_in_data = False

        for task_result in task_results.values():
            data = task_result.get("data", {})
            if not isinstance(data, dict):
                continue

            for finding in data.get("result", []):
                if not isinstance(finding, dict):
                    continue

                if finding.get("code") in ["headers_sql_injection", "headers_time_based_sql_injection"]:
                    headers_dict = finding.get("headers", {})

                    if "User-Agent" in headers_dict:
                        found_headers_in_data = True
                        break

        self.assertTrue(
            found_headers_in_data,
            "The injected headers were not found in the structured 'data' field of the task result.",
        )
