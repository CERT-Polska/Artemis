import os
from typing import Any, Callable, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class WPScannerReporter(Reporter):
    INSECURE_WORDPRESS = ReportType("insecure_wordpress")
    OLD_WORDPRESS = ReportType("old_wordpress")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "wp_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if task_result["result"].get("wp_version_insecure", False):
            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=WPScannerReporter.INSECURE_WORDPRESS,
                    additional_data={"version": task_result["result"]["wp_version"]},
                    timestamp=task_result["created_at"],
                )
            ]
        elif task_result["result"].get("wp_version_old", False):
            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=WPScannerReporter.OLD_WORDPRESS,
                    additional_data={"version": task_result["result"]["wp_version"]},
                    timestamp=task_result["created_at"],
                )
            ]
        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_insecure_wordpress.jinja2"), priority=10
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_old_wordpress.jinja2"), priority=3
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            WPScannerReporter.INSECURE_WORDPRESS: WPScannerReporter.normal_form_rule,
            WPScannerReporter.OLD_WORDPRESS: WPScannerReporter.normal_form_rule,
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

    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "wp_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [
            Asset(
                asset_type=AssetType.CMS,
                name=get_target_url(task_result),
                additional_type="wordpress",
                version=task_result["result"].get("wp_version", None),
            )
        ]
