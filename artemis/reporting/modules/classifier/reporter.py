from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class ClassifierReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        mapping = {
            "domain": AssetType.DOMAIN,
            "ip": AssetType.IP,
        }

        if task_result["result"]["type"].lower() not in mapping:
            return []

        asset_type = mapping[task_result["result"]["type"].lower()]

        result = []
        for item in task_result["result"]["data"]:
            result.append(Asset(asset_type=asset_type, name=item))
        return result
