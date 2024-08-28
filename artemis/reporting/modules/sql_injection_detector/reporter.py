import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class SqlInjectionDetectorReporter(Reporter):
    SQL_INJECTION_CORE = ReportType("sql_injection:core")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "sql_injection_detector":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"{task_result['payload']['host']}",
                report_type=SqlInjectionDetectorReporter.SQL_INJECTION_CORE,
                additional_data=task_result["result"],
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_sql_injection.jinja2"),
                priority=8,
            ),
        ]
