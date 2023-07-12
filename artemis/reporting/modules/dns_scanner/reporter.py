import os
from typing import Any, Callable, Dict, List

from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_domain_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class DNSScannerReporter(Reporter):
    ZONE_TRANSFER_POSSIBLE = ReportType("zone_transfer_possible")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "dns_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if (
            "topmost_transferable_zone_name" in task_result["result"]
            and task_result["result"]["zone_size"] >= Config.Modules.DNSScanner.ZONE_TRANSFER_SIZE_REPORTING_THRESHOLD
        ):
            top_level_target = get_top_level_target(task_result)
            target = task_result["result"]["topmost_transferable_zone_name"]

            # Sometimes when we scan a domain (e.g. something.example.com) we get a report that parent domain
            # allows transfer. In such cases, we need to report this to the parent domain.
            if is_subdomain(top_level_target, target, allow_equal=False):
                top_level_target = target
                is_for_parent_domain = True
            else:
                is_for_parent_domain = False

            return [
                Report(
                    top_level_target=top_level_target,
                    target=target,
                    report_type=DNSScannerReporter.ZONE_TRANSFER_POSSIBLE,
                    additional_data={
                        "zone_transfer_nameserver": task_result["result"]["zone_transfer_nameserver"],
                        "zone_size": task_result["result"]["zone_size"],
                        "is_for_parent_domain": is_for_parent_domain,
                    },
                    timestamp=task_result["created_at"],
                )
            ]
        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_zone_transfer_possible.jinja2"), priority=5
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {
            DNSScannerReporter.ZONE_TRANSFER_POSSIBLE: lambda report: [0],
        }

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            DNSScannerReporter.ZONE_TRANSFER_POSSIBLE: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(report.target),
                    "nameserver": report.additional_data["zone_transfer_nameserver"],
                }
            ),
        }
