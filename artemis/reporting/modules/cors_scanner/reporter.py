from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class CORSScannerReporter(Reporter):
    CORS_MISCONFIGURATION = ReportType("cors_misconfiguration")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "cors_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if not task_result.get("status") == "INTERESTING":
            return []

        findings = task_result["result"].get("findings", [])
        if not findings:
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=CORSScannerReporter.CORS_MISCONFIGURATION,
                additional_data={
                    "findings": findings,
                },
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_cors_misconfiguration.jinja2"),
                priority=4,
            ),
        ]
