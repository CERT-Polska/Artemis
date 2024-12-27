import os
from typing import Any, Dict, List

from artemis.config import Config
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class RemovedDomainExistingVhostReporter(Reporter):
    REMOVED_DOMAIN_EXISTING_VHOST = ReportType("removed_domain_existing_vhost")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "removed_domain_existing_vhost":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if (
            Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_REPORT_ONLY_SUBDOMAINS
            and task_result["result"]["domain"] == task_result["payload_persistent"].get("original_domain")
        ):
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=task_result["result"]["domain"],
                report_type=RemovedDomainExistingVhostReporter.REMOVED_DOMAIN_EXISTING_VHOST,
                additional_data={"ip": task_result["result"]["ip"]},
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_removed_domain_existing_vhost.jinja2"), priority=3
            ),
        ]
