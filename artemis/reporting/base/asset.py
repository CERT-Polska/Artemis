from dataclasses import dataclass

from artemis.reporting.base.asset_type import AssetType


@dataclass
class Asset:
    asset_type: AssetType
    name: str
