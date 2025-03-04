import os
from typing import Any, Callable, Dict, List

from artemis import utils
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target

logger = utils.build_logger(__name__)


class JoomlaExtensionsReporter(Reporter):
    JOOMLA_OUTDATED_EXTENSION = ReportType("joomla_outdated_extension")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "joomla_extensions":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for item in task_result["result"].get("outdated_extensions", []):
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=JoomlaExtensionsReporter.JOOMLA_OUTDATED_EXTENSION,
                    additional_data=item,
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_joomla_outdated_extension.jinja2"), 4
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            JoomlaExtensionsReporter.JOOMLA_OUTDATED_EXTENSION: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "extension_name": report.additional_data["name"],
                    "extension_version_on_website": report.additional_data["version_on_website"],
                }
            ),
        }
