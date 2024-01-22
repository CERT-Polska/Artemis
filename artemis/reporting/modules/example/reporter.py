from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class ExampleReporter(Reporter):
    URL_HAS_EVEN_NUMBER_OF_CHARACTERS = ReportType("url_has_even_number_of_characters")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "example":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        # Here you may add additional heuristics to distinguish false from true positives.

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=ExampleReporter.URL_HAS_EVEN_NUMBER_OF_CHARACTERS,
                timestamp=task_result["created_at"],
                additional_data={"url_length": task_result["result"]["url_length"]},
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_url_has_even_number_of_characters.jinja2"), priority=2
            ),
        ]
