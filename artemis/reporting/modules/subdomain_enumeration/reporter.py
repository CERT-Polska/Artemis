from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class SubdomainEnumerationReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "subdomain_enumeration":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [
            Asset(asset_type=AssetType.DOMAIN, name=domain)
            for domain in task_result["result"].get("existing_domains", [])
        ]
