import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class DomainExpirationScannerReporter(Reporter):
    CLOSE_DOMAIN_EXPIRATION_DATE = ReportType("close_domain_expiration_date")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "domain_expiration_scanner":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        additional_data = task_result["result"]

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"http://{task_result['payload']['domain']}",
                report_type=DomainExpirationScannerReporter.CLOSE_DOMAIN_EXPIRATION_DATE,
                additional_data=additional_data["days_to_expire"],
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_close_domain_expiration_scanner.jinja2"),
                priority=5,
            ),
        ]
