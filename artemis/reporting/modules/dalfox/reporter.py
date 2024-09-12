import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class DalFoxReporter(Reporter):
    """
    Running a report with data generated using the Dalfox tool, which scans URLs for XSS vulnerabilities.
    """

    XSS = ReportType("xss")

    @staticmethod
    def get_alerts(all_reports: List[Report]) -> List[str]:
        result = []

        for report in all_reports:
            if report.report_type == DalFoxReporter.XSS:
                result.append(
                    f"As Dalfox is a new module, verify whether the problem on {report.target} is indeed a true positive."
                )
        return result

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "dalfox":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"{task_result['payload']['host']}",
                report_type=DalFoxReporter.XSS,
                additional_data=task_result["result"],
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_xss.jinja2"), priority=7
            )
        ]
