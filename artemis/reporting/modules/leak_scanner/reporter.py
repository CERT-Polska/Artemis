import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class LeakScannerReporter(Reporter):
    LEAKED_SENSITIVE_DATA = ReportType("leaked_sensitive_data")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "leak_scanner":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        reports = []
        for pdf_data in task_result["result"].get("pdfs_with_leaked_data", []):
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=pdf_data["url"],
                    report_type=LeakScannerReporter.LEAKED_SENSITIVE_DATA,
                    timestamp=task_result["created_at"],
                    additional_data={
                        "leaked_items": pdf_data["leaked_items"],
                        "num_leaked_items": len(pdf_data["leaked_items"]),
                    },
                )
            )
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_leaked_sensitive_data.jinja2"),
                priority=7,
            ),
        ]
