from typing import Any, Dict, List, Optional

from artemis.cpe_tools.cpe_utils import lookup_cpe
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.cpe import extract_cpe
from artemis.reporting.base.reporter import Reporter
from artemis.web_technology_identification import Technology


def _cpe(raw_cpe: Any, name: str) -> Optional[str]:
    return extract_cpe(raw_cpe) or lookup_cpe(name, exact_only=True)


def _iter_technologies(result: Dict[str, Any]) -> List[Technology]:
    """Return technologies from a ``webapp_identifier`` task result."""
    technologies: List[Technology] = []

    structured = result.get("technologies")
    if isinstance(structured, list) and structured:
        for tech in structured:
            if not isinstance(tech, dict):
                continue
            name = tech.get("name")
            if not name:
                continue
            version = tech.get("version") or None
            technologies.append(
                Technology(
                    name=str(name),
                    version=str(version) if version else None,
                    cpe=_cpe(tech.get("cpe", None), str(name)),
                )
            )
        return technologies

    for tag in result.get("technology_tags", []):
        if not isinstance(tag, str):
            continue
        if ":" in tag:
            name, version = tag.split(":", 1)
            technologies.append(Technology(name=name, version=version or None, cpe=_cpe(None, name)))
        else:
            technologies.append(Technology(name=tag, cpe=_cpe(None, tag)))
    return technologies


class WebappIdentifierReporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "webapp_identifier":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for technology in _iter_technologies(task_result["result"]):
            if technology.name == "WordPress":  # we have separate type for that
                result.append(
                    Asset(
                        asset_type=AssetType.CMS,
                        name=task_result["target_string"],
                        additional_type="wordpress",
                        version=technology.version,
                        cpe=technology.cpe,
                    )
                )
            elif technology.name == "Joomla":  # we have separate type for that
                result.append(
                    Asset(
                        asset_type=AssetType.CMS,
                        name=task_result["target_string"],
                        additional_type="joomla",
                        version=technology.version,
                        cpe=technology.cpe,
                    )
                )
            else:
                result.append(
                    Asset(
                        asset_type=AssetType.TECHNOLOGY,
                        name=task_result["target_string"],
                        additional_type=technology.name,
                        version=technology.version,
                        cpe=technology.cpe,
                    )
                )
        return result
