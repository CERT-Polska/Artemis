from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.config import Config
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class HumbleReporter(Reporter):
    MISSING_SECURITY_HEADERS = ReportType("missing_security_headers")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "humble":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=HumbleReporter.MISSING_SECURITY_HEADERS,
                additional_data={
                    "message_data": HumbleReporter._filter_message_data(task_result["result"]["message_data"]),
                },
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_missing_security_headers.jinja2"), priority=2
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            HumbleReporter.MISSING_SECURITY_HEADERS: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "message_data": [Reporter.dict_to_tuple(item) for item in report.additional_data["message_data"]],
                }
            )
        }

    @staticmethod
    def _filter_message_data(message_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for item in message_data:
            if item["category"] == "Missing http security headers":
                problems = sorted(set(item["problems"]) & set(Config.Modules.Humble.HUMBLE_HEADERS_TO_REPORT))
                if problems:
                    result.append({"category": item["category"], "problems": problems})
            else:
                result.append(item)
        return result
