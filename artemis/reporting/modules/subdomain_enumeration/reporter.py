from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class SubdomainEnumerationReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        return [Asset(asset_type=AssetType.DOMAIN, name=domain) for domain in task_result["result"]["existing_domains"]]
