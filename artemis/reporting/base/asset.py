from dataclasses import dataclass
from typing import Optional

from artemis.reporting.base.asset_type import AssetType


@dataclass
class Asset:
    asset_type: AssetType
    name: str

    # Data about the original task result that led to the creation of this Report
    original_karton_name: Optional[str] = None

    # What was the last domain observed when scanning (e.g. when we started with example.com, then proceeded to
    # subdomain1.example.com, then resolved it to an IP and found a vulnerability on this IP, last_domain would be
    # subdomain1.example.com).
    last_domain: Optional[str] = None
