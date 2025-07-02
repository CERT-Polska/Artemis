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


class APIScannerReporter(Reporter):
    API_VULNERABILITY = ReportType("api_vulnerability")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "api_scanner":
            return []

        if task_result["status"] != "INTERESTING":
            return []

        if not isinstance(task_result.get("result"), dict) or not isinstance(
            task_result["result"].get("results"), list
        ):
            return []

        reports = []
        for result in task_result["result"]["results"]:
            url = result["url"]

            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=url,
                    report_type=APIScannerReporter.API_VULNERABILITY,
                    additional_data={
                        "method": result.get("method"),
                        "endpoint": result.get("endpoint"),
                        "data_leak": result.get("data_leak"),
                        "details": result.get("vuln_details"),
                        "curl_command": result.get("curl_command"),
                        "status_code": result.get("status_code"),
                    },
                    timestamp=task_result["created_at"],
                )
            )

        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_api_vulnerability.jinja2"),
                priority=6,  # Slightly lower than specific vulns but still important
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        return {
            APIScannerReporter.API_VULNERABILITY: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(urllib.parse.urlparse(report.target).hostname or ""),
                    "endpoint": urllib.parse.urlparse(report.target).path,
                    "vulnerability_type": report.additional_data.get("vulnerability_type", "unknown"),
                }
            )
        }
