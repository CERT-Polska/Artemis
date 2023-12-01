import os
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class DrupalScannerReporter(Reporter):
    OLD_DRUPAL = ReportType("old_drupal")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "drupal_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if task_result["result"].get("is_version_obsolete", False):
            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=DrupalScannerReporter.OLD_DRUPAL,
                    additional_data={"version": task_result["result"]["version"]},
                    timestamp=task_result["created_at"],
                )
            ]
        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_old_drupal.jinja2"), priority=5
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            DrupalScannerReporter.OLD_DRUPAL: DrupalScannerReporter.normal_form_rule,
        }

    @staticmethod
    def normal_form_rule(report: Report) -> NormalForm:
        return Reporter.dict_to_tuple(
            {
                "type": report.report_type,
                "target": get_url_normal_form(report.target),
                "version": report.additional_data["version"],
            }
        )
