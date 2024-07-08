import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target
from artemis.resolvers import ResolutionException, lookup


class FTPBruterReporter(Reporter):
    WRITABLE_FTP = ReportType("writable_ftp")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ftp_bruter":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        try:
            ips = list(lookup(task_result["payload"]["host"]))
            if ips:
                host = ips[0]
            else:
                host = task_result["payload"]["host"]
        except ResolutionException:
            return []

        if task_result["result"].get("is_writable", False):
            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f"ftp://{host}:{task_result['payload']['port']}",
                    additional_data={"credentials": task_result["result"]["credentials"]},
                    report_type=FTPBruterReporter.WRITABLE_FTP,
                    timestamp=task_result["created_at"],
                )
            ]
        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_writable_ftp.jinja2"),
                priority=7,
            ),
        ]
