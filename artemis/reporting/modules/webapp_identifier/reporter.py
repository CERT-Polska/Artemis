from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class WebappIdentifierReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "webapp_identifier":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for tag in task_result["result"].get("technology_tags", []):
            result.append(Asset(asset_type=AssetType.TECHNOLOGY, name=task_result["target_string"], additional_type=tag))
        return result
