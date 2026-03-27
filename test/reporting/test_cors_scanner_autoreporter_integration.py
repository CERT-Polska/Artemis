from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.cors_scanner import CorsScanner
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class CorsScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = CorsScanner  # type: ignore

    def test_cors_misconfiguration_message(self) -> None:
        message = self._run_task_and_get_message("test-cors-vulnerable")
        self.assertIn(
            "CORS misconfiguration",
            message,
        )
        self.assertIn(
            "https://evil.com",
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
                "type": "service",
                "service": "http",
                "receiver": "cors_scanner",
            },
            "payload": {
                "port": 80,
                "host": host,
                "last_domain": host,
            },
            "payload_persistent": {
                "original_domain": host,
            },
            "status": "INTERESTING",
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
