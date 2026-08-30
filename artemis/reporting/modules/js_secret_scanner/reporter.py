import os
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class JSSecretScannerReporter(Reporter):
    """Reporter for the ``js_secret_scanner`` module.

    Generates one report per target when secrets are detected.  The report
    embeds already-redacted secret values so that they can be included
    verbatim in e-mail notifications.
    """

    JS_SECRET_LEAK = ReportType("js_secret_leak")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "js_secret_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if task_result["status"] != "INTERESTING":
            return []

        secrets = task_result["result"].get("secrets_found")
        if not secrets:
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=JSSecretScannerReporter.JS_SECRET_LEAK,
                timestamp=task_result["created_at"],
                additional_data={"secrets_found": secrets},
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_js_secret_leak.jinja2"),
                priority=9,
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            JSSecretScannerReporter.JS_SECRET_LEAK: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                }
            ),
        }
