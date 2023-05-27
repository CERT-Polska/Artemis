import os
import socket
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import cached_gethostbyname, get_top_level_target


class MySQLBruterReporter(Reporter):
    EXPOSED_DATABASE_WITH_EASY_PASSWORD = ReportType("exposed_database_with_easy_password")

    @staticmethod
    def get_report_types() -> List[ReportType]:
        return [MySQLBruterReporter.EXPOSED_DATABASE_WITH_EASY_PASSWORD]

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "mysql_bruter":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        try:
            ip_address = cached_gethostbyname(task_result["payload"]["host"])
        except socket.gaierror:
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"mysql://{ip_address}:{task_result['payload']['port']}",
                report_type=MySQLBruterReporter.EXPOSED_DATABASE_WITH_EASY_PASSWORD,
                report_data={"credentials": task_result["result"]["credentials"]},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_database_with_easy_password.jinja2"), 8
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {
            MySQLBruterReporter.EXPOSED_DATABASE_WITH_EASY_PASSWORD: Reporter.default_scoring_rule,
        }

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            MySQLBruterReporter.EXPOSED_DATABASE_WITH_EASY_PASSWORD: Reporter.default_normal_form_rule,
        }
