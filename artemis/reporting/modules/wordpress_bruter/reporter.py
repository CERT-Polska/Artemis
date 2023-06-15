import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class WordPressBruterReporter(Reporter):
    EXPOSED_WORDPRESS_WITH_EASY_PASSWORD = ReportType("exposed_wordpress_with_easy_password")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "wordpress_bruter":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=WordPressBruterReporter.EXPOSED_WORDPRESS_WITH_EASY_PASSWORD,
                additional_data={"credentials": task_result["result"]},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_wordpress_with_easy_password.jinja2"),
                priority=8,
            ),
        ]
