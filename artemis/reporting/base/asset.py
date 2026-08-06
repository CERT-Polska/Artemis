import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

from artemis.domains import is_domain
from artemis.ip_utils import is_ip_address
from artemis.reporting.base.asset_type import AssetType
from artemis.resolvers import ResolutionException, lookup


@dataclass
class Asset:
    asset_type: AssetType
    name: str
    additional_type: Optional[str] = None
    version: Optional[str] = None

    # Common Platform Enumeration (https://en.wikipedia.org/wiki/Common_Platform_Enumeration) name of the
    # software the asset runs, e.g. cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*. Being a structured and
    # standardized identifier, it makes it possible to match an asset against e.g. the CVE database, which
    # the free-form `additional_type` doesn't.
    #
    # The CPE is saved as reported by the source, which means the version slot is usually a wildcard even if we
    # do know the version - the version is kept in the `version` field above instead. A consumer that needs a
    # versioned CPE (e.g. to query the NVD API) should combine the two.
    #
    # For the same reason the binding isn't guaranteed either: this is usually a CPE 2.3 formatted string
    # (cpe:2.3:a:vendor:product:...), but a source may as well provide the older CPE 2.2 URI
    # (cpe:/a:vendor:product) - a consumer parsing the value needs to handle both.
    #
    # Not all modules are able to provide it, and even the ones that are can only pass on what the source
    # knows - both the Nuclei templates and the Wappalyzer fingerprint database describe a CPE for a minority
    # of what they detect. An empty `cpe` is the normal case, not a sign that something went wrong.
    cpe: Optional[str] = None

    # Data about the IP address of the asset
    domain_ips: Optional[List[str]] = field(init=False)

    # Data about the original task result that led to the creation of this Asset
    original_karton_name: Optional[str] = None
    original_task_result_id: Optional[str] = None

    # What was the last domain observed when scanning (e.g. when we started with example.com, then proceeded to
    # subdomain1.example.com, then resolved it to an IP and found an asset on this IP, last_domain would be
    # subdomain1.example.com).
    last_domain: Optional[str] = None

    # top_level_target is the target that was provided when adding targets to be scanned. It may not be the same as
    # the target where actual asset was found - e.g. you may start with scanning example.com and the
    # asset may be found on https://subdomain.example.com/phpmyadmin/
    top_level_target: Optional[str] = None

    def __post_init__(self) -> None:
        if "://" in self.name:
            data = urllib.parse.urlparse(self.name)
            host = data.hostname
        elif ":" in self.name:
            host = self.name.split(":")[0]
        else:
            host = self.name

        if host is None:
            self.domain_ips = None
            return

        if is_ip_address(host):
            self.domain_ips = [host]
        elif is_domain(host):
            try:
                self.domain_ips = list(lookup(host))
            except ResolutionException:
                self.domain_ips = []
        else:
            self.domain_ips = None
