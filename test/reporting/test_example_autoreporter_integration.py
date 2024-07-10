from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.example import Example
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class ExampleAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Example  # type: ignore

    def test_example(self) -> None:
        message = self._run_task_and_get_message("test-nginx")
        self.assertIn(
            "<li>We identified that the following URLs have even number of characters:",
            message,
        )
        self.assertIn(
            "http://test-nginx:80: 20 characters",
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
                "receiver": "example",
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
