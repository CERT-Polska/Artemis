from dataclasses import dataclass
from typing import Optional

from artemis.reporting.base.asset_type import AssetType


@dataclass
class Asset:
    asset_type: AssetType
    name: str
    additional_type: Optional[str] = None
    version: Optional[str] = None

    # Data about the original task result that led to the creation of this Asset
    original_karton_name: Optional[str] = None

    # What was the last domain observed when scanning (e.g. when we started with example.com, then proceeded to
    # subdomain1.example.com, then resolved it to an IP and found an asset on this IP, last_domain would be
    # subdomain1.example.com).
    last_domain: Optional[str] = None

    # top_level_target is the target that was provided when adding targets to be scanned. It may not be the same as
    # the target where actual asset was found - e.g. you may start with scanning example.com and the
    # asset may be found on https://subdomain.example.com/phpmyadmin/
    top_level_target: Optional[str] = None
