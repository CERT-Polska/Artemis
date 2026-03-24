import os
from typing import Any, Dict, List

from artemis.modules.ssh_bad_keys import SSHBadKeysResult
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class SSHBadKeysReporter(Reporter):
    SSH_KNOWN_BAD_KEY = ReportType("ssh_known_bad_key")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ssh_bad_keys":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if isinstance(task_result["result"], dict):
            task_result["result"] = SSHBadKeysResult(**task_result["result"])

        data = task_result["result"]
        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"ssh://{task_result['payload']['host']}/",
                report_type=SSHBadKeysReporter.SSH_KNOWN_BAD_KEY,
                additional_data={
                    "bad_keys": [bk.model_dump() for bk in data.bad_keys],
                },
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_ssh_known_bad_key.jinja2"),
                priority=10,
            ),
        ]
