from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class ClassifierReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "classifier":
            return []

        mapping = {
            "domain": AssetType.DOMAIN,
            "ip": AssetType.IP,
        }

        if not isinstance(task_result["result"], dict):
            return []

        if task_result["result"]["type"].lower() not in mapping:
            return []

        asset_type = mapping[task_result["result"]["type"].lower()]

        result = []
        for item in task_result["result"].get("data", []):
            result.append(Asset(asset_type=asset_type, name=item))
        return result
