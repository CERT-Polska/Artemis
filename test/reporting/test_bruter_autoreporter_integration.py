from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.bruter import Bruter
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class BruterAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Bruter  # type: ignore

    def test_sql_dumps(self) -> None:
        message = self._run_task_and_get_message("test-service-with-bruteable-files-sql-dumps")
        self.assertIn(
            "<li>The following files contain database dumps:",
            message,
        )
        self.assertIn(
            "http://test-service-with-bruteable-files-sql-dumps:80/localhost.sql",
            message,
        )

    def test_htpasswd(self) -> None:
        message = self._run_task_and_get_message("test-service-with-bruteable-files-htpasswd")
        self.assertIn(
            "<li>The following files contain passwords or password hashes:",
            message,
        )
        self.assertIn(
            "http://test-service-with-bruteable-files-htpasswd:80/_.htpasswd",
            message,
        )

    def _run_task_and_get_message(self, host: str) -> str:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": 80},
            payload_persistent={"original_domain": host},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        data = {
            "created_at": None,
            "headers": {
                "receiver": "bruter",
            },
            "payload": {
                "last_domain": host,
            },
            "payload_persistent": {
                "original_domain": host,
            },
            "result": call.kwargs["data"],
        }

        reports = reports_from_task_result(data, Language.en_US)  # type: ignore
        message_template = self.generate_message_template()
        return message_template.render(
            {
                "data": {
                    "custom_template_arguments": {},
                    "contains_type": set([report.report_type for report in reports]),
                    "reports": reports,
                }
            }
        )
