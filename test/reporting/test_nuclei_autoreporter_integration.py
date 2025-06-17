from test.base import BaseReportingTest
from typing import Any, Dict

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.nuclei import Nuclei
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import (
    assets_from_task_result,
    reports_from_task_result,
)


class NucleiAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Nuclei  # type: ignore

    def test_reporting(self, host: str) -> None:
        data = self._obtain_task_result("test-phpmyadmin-easy-password")
        message = self._task_result_to_message(data)
        print(message)

    def test_asset_discovery(self, host: str) -> None:
        data = self._obtain_task_result("test-old-wordpress")
        message = self._task_result_to_message(data)
        print(message)
        # this should not be reported as WordPress panel detection template is skipped from reporting (but not from running)
        self.assertNotIn("test-old-wordpress", message)
        assets = assets_from_task_result(data, Language.en_US)  # type: ignore
        print(assets)

    def _obtain_task_result(self, host: str) -> Dict[str, Any]:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": 80},
            payload_persistent={"original_domain": host},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        return {
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

    def _task_result_to_message(self, data: Dict[str, Any]) -> str:
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
