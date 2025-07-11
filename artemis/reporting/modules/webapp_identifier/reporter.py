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
            if ":" in tag:
                technology, version = tag.split(":", 1)
            else:
                technology = tag
                version = None

            if technology == "WordPress":  # we have separate type for that
                result.append(
                    Asset(
                        asset_type=AssetType.CMS,
                        name=task_result["target_string"],
                        additional_type="wordpress",
                        version=version,
                    )
                )
            elif technology == "Joomla":  # we have separate type for that
                result.append(
                    Asset(
                        asset_type=AssetType.CMS,
                        name=task_result["target_string"],
                        additional_type="joomla",
                        version=version,
                    )
                )
            else:
                result.append(
                    Asset(
                        asset_type=AssetType.TECHNOLOGY,
                        name=task_result["target_string"],
                        additional_type=technology,
                        version=version,
                    )
                )
        return result
