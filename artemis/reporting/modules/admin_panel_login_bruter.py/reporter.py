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


class BruteforceLoginReporter(Reporter):
    BRUTEFORCE_LOGIN = ReportType("bruteforce_login")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "bruteforce_login":
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
                url = result["target"]
                parsed_url = urllib.parse.urlparse(url)
                ips = list(lookup(parsed_url.hostname)) if parsed_url.hostname else []
                resolved_host = ips[0] if ips else parsed_url.hostname
            except (ResolutionException, KeyError, AttributeError):
                continue

            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=url,
                    report_type=BruteforceLoginReporter.BRUTEFORCE_LOGIN,
                    additional_data={
                        "credentials": result["credentials"],
                        "resolved_host": resolved_host,
                        "indicators": result.get("indicators", []),
                    },
                    timestamp=task_result["created_at"],
                )
            )
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_bruteforce_login.jinja2"),
                priority=5,
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            BruteforceLoginReporter.BRUTEFORCE_LOGIN: lambda report: Reporter.dict_to_tuple({
                "type": report.report_type,
                "target": get_domain_normal_form(
                    urllib.parse.urlparse(report.target).hostname or ""
                ),
            })
        }
