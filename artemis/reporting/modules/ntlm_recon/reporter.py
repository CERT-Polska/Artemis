from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment


class NTLMReconReporter(Reporter):
    EXPOSED_NTLM_ENDPOINT = ReportType("exposed_ntlm_endpoint")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ntlm_recon":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if task_result["status"] != "INTERESTING":
            return []

        reports = []
        for endpoint in task_result["result"].get("ntlm_endpoints", []):
            reports.append(
                Report(
                    top_level_target=task_result["target_string"],
                    target=endpoint["url"],
                    report_type=NTLMReconReporter.EXPOSED_NTLM_ENDPOINT,
                    timestamp=task_result["created_at"],
                    additional_data={
                        "ntlm_info": endpoint.get("data", {}),
                        "decoded": endpoint.get("decoded", False),
                    },
                )
            )
        return reports

    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "ntlm_recon":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        assets = []
        for endpoint in task_result["result"].get("ntlm_endpoints", []):
            ad_domain = endpoint.get("data", {}).get("AD domain name")
            assets.append(
                Asset(
                    asset_type=AssetType.NTLM_ENDPOINT,
                    name=endpoint["url"],
                    additional_type=ad_domain or "ntlm",
                )
            )
        return assets

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_exposed_ntlm_endpoint.jinja2"),
                priority=3,
            ),
        ]
