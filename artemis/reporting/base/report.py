import copy
import datetime
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from artemis.domains import is_domain
from artemis.ip_utils import is_ip_address
from artemis.reporting.severity import Severity
from artemis.resolvers import ResolutionException, lookup
from artemis.utils import get_host_from_url

from .normal_form import NormalForm
from .report_type import ReportType
from .reporters import get_all_reporters


@dataclass
class Report:
    # top_level_target is the target that was provided when adding targets to be scanned. It may not be the same as
    # the target where actual vulnerability was found - e.g. you may start with scanning example.com and the
    # vulnerability may be found on https://subdomain.example.com/phpmyadmin/
    top_level_target: str

    # The actual location of the vulnerability (it may be e.g. a domain or a URL)
    target: str
    report_type: ReportType

    # Additional report data - the content depends on the report type
    additional_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime.datetime] = None

    # === All following variables are provided automatically, you don't have to provide them when creating a Report
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

    # IP address of the target - used later to deduplicate identical vulnerabilities on a domain and on an IP of the
    # domain.
    target_ip: Optional[str] = None

    # Whether an attempt to resolve the IP of the target has been performed (the IP may be None because it has not been
    # checked or because the domain didn't resolve).
    target_ip_checked: bool = False

    # Whether we already reported that vulnerability earlier
    is_subsequent_reminder: bool = False

    # Whether Artemis considers this report low-confidence
    is_suspicious: bool = False

    # What was the last domain observed when scanning (e.g. when we started with example.com, then proceeded to
    # subdomain1.example.com, then resolved it to an IP and found a vulnerability on this IP, last_domain would be
    # subdomain1.example.com).
    last_domain: Optional[str] = None

    # The tag that has been added by the user when adding target to scan
    tag: Optional[str] = None

    # Data about the original task result that led to the creation of this Report
    original_karton_name: Optional[str] = None
    original_task_result_id: Optional[str] = None
    original_task_result_root_uid: Optional[str] = None
    original_task_target_string: Optional[str] = None

    # The severity (added during report post-processing)
    severity: Optional[Severity] = None

    # The normal form (added during report post-processing)
    normal_form: Optional[NormalForm] = None

    # HTML render of the report (added during post-processing)
    html: Optional[str] = None

    def __post_init__(self) -> None:
        # Sanity check - at this moment, only URLs and domains are supported
        assert self.target_is_url() or self.target_is_domain()

        if not self.target_ip_checked:
            # If something is a domain let's skip obtaining IP as domain-related vulnerabilities
            # (e.g. zone transfer or DMARC problems) don't have sensible IP versions.
            if self.target_is_url():
                host = get_host_from_url(self.target)
                if is_ip_address(host):
                    self.target_ip = host
                else:
                    try:
                        ips = list(lookup(host))
                        self.target_ip = ips[0] if ips else None
                    except ResolutionException:
                        self.target_ip = None
            self.target_ip_checked = True

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Report):
            return False

        return (
            self.top_level_target == other.top_level_target
            and self.target == other.target
            and self.report_type == other.report_type
            and self.additional_data == other.additional_data
        )

    def target_is_ip_address(self) -> bool:
        if self.target_is_url():
            host = get_host_from_url(self.target)
            return is_ip_address(host)
        else:
            return is_ip_address(self.target)

    def target_is_url(self) -> bool:
        try:
            result = urllib.parse.urlparse(self.target)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def target_is_domain(self) -> bool:
        if self.target_is_url():
            return False

        assert ":" not in self.target
        return True

    def alternative_with_ip_address(self) -> Optional["Report"]:
        """If a report is about a URL where the host is a domain, not an IP, returns a version of this report
        where the domain is replaced with an IP. Otherwise returns None.

        **Such an alternative vulnerability doesn't necessairly have to exist.** There is plenty of cases
        where vulnerability exists only by domain, not by IP. The purpose of this method is to return a potential
        IP version for deduplication (so that we don't return a vulnerability on IP if we see identical one
        on a domain resolving to this IP).
        """
        if self.target_is_url() and not self.target_is_ip_address() and self.target_ip:
            report = copy.deepcopy(self)
            target_parsed = urllib.parse.urlparse(self.target)
            target_parsed_dict = target_parsed._asdict()
            if target_parsed.port:
                port_suffix = ":" + str(target_parsed.port)
            else:
                port_suffix = ""
            target_parsed_dict["netloc"] = self.target_ip + port_suffix
            report.target = urllib.parse.urlunparse(urllib.parse.ParseResult(**target_parsed_dict))
            return report
        return None

    def get_normal_form(self) -> NormalForm:
        """Returns the normal form of the report - if multiple reports have the same normal form,
        only one of them should be reported. Score (returned by get_score()) determines which one."""
        for reporter in get_all_reporters():
            normal_form_rules = reporter.get_normal_form_rules()
            if self.report_type in normal_form_rules:
                return normal_form_rules[self.report_type](self)  # type: ignore
        raise NotImplementedError(f"Don't know how to get normal form for {self.report_type}")

    def get_score(self) -> List[int]:
        """Returns a score: different reports with the same normal form may have different scores depending
        how good this version is - e.g. https://domain.com/wp-config.php.bak is better than http://www.domain.com/wp-config.php.bak.

        Among reports with the same normal form, the report with the highest score will be sent (or one chosen from
        many reports with the highest score).

        Score is a list of ints that should be compared lexicographically (the ints should be compared in a standard way).
        """

        for reporter in get_all_reporters():
            scoring_rules = reporter.get_scoring_rules()
            if self.report_type in scoring_rules:
                return scoring_rules[self.report_type](self)  # type: ignore
        raise NotImplementedError(f"Don't know how to get score for {self.report_type}")

    def get_domain(self) -> Optional[str]:
        if is_domain(self.target):
            return self.target

        assert self.target_is_url()
        hostname = urllib.parse.urlparse(self.target).hostname
        assert hostname

        if is_domain(hostname):
            return hostname

        assert is_ip_address(hostname)
        if self.last_domain:
            return self.last_domain

        if is_domain(self.top_level_target):
            return self.top_level_target

        return None
