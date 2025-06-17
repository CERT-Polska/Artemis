from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.bruter import Bruter
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result, assets_from_task_result


class NucleiAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Bruter  # type: ignore

    def test_reporting_and_asset_discovery(self, host: str) -> str:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": 80},
            payload_persistent={"original_domain": "test-old-wordpress"},
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
        message = message_template.render(
            {
                "data": {
                    "custom_template_arguments": {},
                    "contains_type": set([report.report_type for report in reports]),
                    "reports": reports,
                }
            }
        )
        print(message)
        assets = assets_from_task_result(data, Language.en_US)  # type: ignore
        print(assets)
