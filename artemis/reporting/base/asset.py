from typing import Optional
from dataclasses import dataclass

from artemis.reporting.base.asset_type import AssetType


@dataclass
class Asset:
    asset_type: AssetType
    name: str

    # Data about the original task result that led to the creation of this Report
    original_karton_name: Optional[str] = None
