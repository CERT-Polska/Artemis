import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class WeakAdminCredentialsReporter(Reporter):
    WEAK_ADMIN_CREDENTIALS = ReportType("weak_admin_credentials")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "admin_panel_login_bruter":
            return []

        if task_result["status"] != "INTERESTING":
            return []

        if not isinstance(task_result.get("result", {}).get("results"), list):
            return []

        reports = []
        for result in task_result["result"]["results"]:
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=result["url"],
                    report_type=WeakAdminCredentialsReporter.WEAK_ADMIN_CREDENTIALS,
                    additional_data={
                        "credentials": [result["username"], result["password"]],
                    },
                    timestamp=task_result["created_at"],
                )
            )
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_weak_admin_credentials.jinja2"),
                priority=10,
            ),
        ]
