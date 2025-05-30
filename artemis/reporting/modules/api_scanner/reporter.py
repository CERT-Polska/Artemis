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
from artemis.resolvers import lookup, ResolutionException


class APIHackingReporter(Reporter):
    API_VULNERABILITY = ReportType("api_vulnerability")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "api_scanner":
            return []

        if task_result["status"] != "INTERESTING":
            return []

        if not isinstance(task_result.get("data"), dict) or not isinstance(
            task_result["data"].get("results"), list
        ):
            return []

        reports = []
        for result in task_result["data"]["results"]:
            try:
                url = result["url"]
                parsed_url = urllib.parse.urlparse(url)

                # Resolve hostname to IP
                ips = list(lookup(parsed_url.hostname)) if parsed_url.hostname else []
                resolved_host = ips[0] if ips else parsed_url.hostname

                reports.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=url,
                        report_type=APIHackingReporter.API_VULNERABILITY,
                        additional_data={
                            "method": result["method"],
                            "vulnerability_type": result.get("vulnerability_type", "unknown"),
                            "details": result["details"],
                            "curl_command": result["curl_command"],
                            "status_code": result["status_code"],
                            "resolved_host": resolved_host,
                        },
                        timestamp=task_result["created_at"],
                    )
                )
            except (ResolutionException, KeyError, AttributeError):
                continue

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
            APIHackingReporter.API_VULNERABILITY: lambda report: Reporter.dict_to_tuple({
                "type": report.report_type,
                "target": get_domain_normal_form(
                    urllib.parse.urlparse(report.target).hostname or ""
                ),
                "endpoint": urllib.parse.urlparse(report.target).path,
                "vulnerability_type": report.additional_data.get("vulnerability_type", "unknown"),
            })
        }
