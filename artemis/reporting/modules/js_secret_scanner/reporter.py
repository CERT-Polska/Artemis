from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target


class JSSecretScannerReporter(Reporter):
    EXPOSED_SECRETS_IN_JS = ReportType("exposed_secrets_in_js")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "js_secret_scanner":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if not task_result.get("status") == "INTERESTING":
            return []

        findings = task_result["result"].get("findings", [])
        if not findings:
            return []

        high_findings = [f for f in findings if f["severity"] == "high"]
        medium_findings = [f for f in findings if f["severity"] == "medium"]

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=get_target_url(task_result),
                report_type=JSSecretScannerReporter.EXPOSED_SECRETS_IN_JS,
                additional_data={
                    "findings": findings,
                    "high_count": len(high_findings),
                    "medium_count": len(medium_findings),
                    "secret_types": sorted(set(f["pattern_name"] for f in findings)),
                },
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_exposed_secrets_in_js.jinja2"),
                priority=8,
            ),
        ]
