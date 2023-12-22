import os
from typing import Any, Callable, Dict, List

from artemis.domains import is_subdomain
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target

FILTERED_DOMAINS = ["amazonaws.com", "cloudfront.net"]


class ScriptsUnregisteredDomainsReporter(Reporter):
    SCRIPT_UNREGISTERED_DOMAIN = ReportType("script_unregistered_domain")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "scripts_unregistered_domains":
            return []

        if not isinstance(task_result["result"], list):
            return []

        result = []
        for item in task_result["result"]:
            domain = item["domain"].strip(".")
            if any(is_subdomain(domain, filtered_domain) for filtered_domain in FILTERED_DOMAINS):
                continue

            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=ScriptsUnregisteredDomainsReporter.SCRIPT_UNREGISTERED_DOMAIN,
                    additional_data={"src": item["src"], "domain": domain, "privatesuffix": item["privatesuffix"]},
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_script_unregistered_domain.jinja2"), 9
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            ScriptsUnregisteredDomainsReporter.SCRIPT_UNREGISTERED_DOMAIN: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "privatesuffix": report.additional_data["privatesuffix"] or report.additional_data["domain"],
                }
            ),
        }
