from typing import Any, Dict, List, Optional, Tuple

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


def _iter_technologies(result: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
    """
    Yield ``(name, version)`` pairs from a ``webapp_identifier`` task result.

    Prefers the structured ``technologies`` list; falls back to the legacy
    ``technology_tags`` string list so reports for older task results still
    render.
    """
    pairs: List[Tuple[str, Optional[str]]] = []

    structured = result.get("technologies")
    if isinstance(structured, list) and structured:
        for tech in structured:
            if not isinstance(tech, dict):
                continue
            name = tech.get("name")
            if not name:
                continue
            version = tech.get("version") or None
            pairs.append((str(name), str(version) if version else None))
        return pairs

    for tag in result.get("technology_tags", []):
        if not isinstance(tag, str):
            continue
        if ":" in tag:
            name, version = tag.split(":", 1)
            pairs.append((name, version or None))
        else:
            pairs.append((tag, None))
    return pairs


class WebappIdentifierReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "webapp_identifier":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for technology, version in _iter_technologies(task_result["result"]):
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
