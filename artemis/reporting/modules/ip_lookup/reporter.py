from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class IPLookupReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "ip_lookup":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        return [Asset(asset_type=AssetType.IP, name=ip) for ip in task_result["result"].get("ips", [])]
