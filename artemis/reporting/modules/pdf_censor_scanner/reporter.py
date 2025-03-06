import os
import urllib.parse
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_domain_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class PDFCensorScannerReporter(Reporter):
    CENSORSHIP_WEAKNESS = ReportType("censorship_weakness")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        """Creates reports for weak PDF censorships detected by PDFCensorScanner."""

        # Ensure the report is for the correct module
        if task_result["headers"]["receiver"] != "pdf_censor_scanner":
            return []

        # Only report issues if the task was marked as INTERESTING
        if task_result["status"] != "INTERESTING":
            return []

        # Ensure results are valid
        if not isinstance(task_result.get("result"), dict):
            return []

        pdf_url = task_result["result"]["result"][0]["url"]
        detected_text = task_result["result"].get("detected_text", {})

        if not detected_text:
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=pdf_url,
                report_type=PDFCensorScannerReporter.CENSORSHIP_WEAKNESS,
                additional_data={"detected_issues": detected_text},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        """Returns the email template fragment for redaction warnings."""
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template.jinja2"),
                priority=8,
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """Defines normalization rules for deduplication."""
        return {
            PDFCensorScannerReporter.CENSORSHIP_WEAKNESS: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(urllib.parse.urlparse(report.target).hostname or ""),
                }
            )
        }
