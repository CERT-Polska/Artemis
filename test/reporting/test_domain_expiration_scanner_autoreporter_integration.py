from test.base import BaseReportingTest
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.domain_expiration_scanner import DomainExpirationScanner
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class DomainExpirationScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = DomainExpirationScanner  # type: ignore

    def test_domain_expiration(self) -> None:
        message = self._run_task_and_get_message("google.com")
        self.assertIn("The following domains will soon expire:", message)
        self.assertIn("google.com", message)

    def _run_task_and_get_message(self, domain: str) -> str:
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: domain},
        )
        with patch("artemis.config.Config.Modules.DomainExpirationScanner") as mocked_config:
            mocked_config.DOMAIN_EXPIRATION_TIMEFRAME_DAYS = 5000
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            data = {
                "created_at": None,
                "headers": {
                    "receiver": "domain_expiration_scanner",
                },
                "payload": {
                    "domain": domain,
                },
                "payload_persistent": {
                    "original_domain": domain,
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
