from pathlib import Path
from typing import Any, Callable, Dict, List

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

        result = []
        result.append(
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=HumbleReporter.MISSING_SECURITY_HEADERS,
                additional_data={
                    "message_data": task_result["result"]["message_data"],
                    "messages": task_result["result"]["messages"],
                },
                timestamp=task_result["created_at"],
            )
        )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_missing_security_header.jinja2"), priority=2
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
                    "messages": tuple(report.additional_data["messages"]),  # type: ignore
                }
            )
        }
