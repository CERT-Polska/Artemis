import os
from typing import Any, Dict, List

from artemis.modules.ssh_bruter import SSHBruterResult
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class SSHBruterReporter(Reporter):
    EXPOSED_SSH_WITH_EASY_PASSWORD = ReportType("exposed_ssh_with_easy_password")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ssh_bruter":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if isinstance(task_result["result"], dict):
            task_result["result"] = SSHBruterResult(**task_result["result"])

        data = task_result["result"]
        additional_data = data.credentials
        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"ssh://{task_result['payload']['host']}/",
                report_type=SSHBruterReporter.EXPOSED_SSH_WITH_EASY_PASSWORD,
                additional_data={"credentials": additional_data},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_ssh_with_easy_password.jinja2"),
                priority=10,
            ),
        ]
