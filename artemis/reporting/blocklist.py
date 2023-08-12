import dataclasses
import datetime
import ipaddress
from typing import List, Optional, Union

import yaml

from artemis.domains import is_domain, is_subdomain
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType


@dataclasses.dataclass
class BlocklistItem:
    domain: Optional[str] = None
    ip_range: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None
    target_should_contain: Optional[str] = None
    until: Optional[datetime.datetime] = None
    report_type: Optional[ReportType] = None


class BlocklistError(Exception):
    pass


def load_blocklist(file_path: Optional[str]) -> List[BlocklistItem]:
    if not file_path:
        return []

    with open(file_path, "r") as file:
        data = yaml.safe_load(file)

    for item in data:
        # Assert there are no additional or missing keys
        unexpected_keys = set(item.keys()) - {"domain", "ip_range", "target_should_contain", "until", "report_type"}
        if unexpected_keys:
            raise BlocklistError(f"Unexpected keys in entry: {','.join(unexpected_keys)}")

    blocklist_items = [
        BlocklistItem(
            domain=item.get("domain", None),
            ip_range=ipaddress.ip_network(item["ip_range"], strict=False) if item.get("ip_range", None) else None,
            target_should_contain=item.get("target_should_contain", None),
            until=datetime.datetime.strptime(item["until"], "%Y-%m-%d") if item.get("until", None) else None,
            report_type=item["report_type"] if item.get("report_type", None) else None,
        )
        for item in data
    ]

    return blocklist_items


def filter_blocklist(reports: List[Report], blocklist: List[BlocklistItem]) -> List[Report]:
    result = []
    for report in reports:
        filtered = False
        # each BlocklistItem is a filter that:
        # - if `domain` is set, filters only a domain and its subdomains,
        # - if `ip_range` is set, filters only a given IP range
        # - if `target_should_contain` is set, filters only reports containing a given string in target
        # - if `until` is set, filters only reports earlier than a given date,
        # - if `report_type` is set, filters only reports with given type.
        # If at least one filter matches, report is skipped.
        for item in blocklist:
            if item.domain:
                domain = report.top_level_target if is_domain(report.top_level_target) else None
                if report.last_domain:
                    domain = report.last_domain
                if domain and not is_subdomain(domain, item.domain):
                    continue

            if item.ip_range and report.target_ip and ipaddress.IPv4Address(report.target_ip) in item.ip_range:
                continue

            if item.target_should_contain and item.target_should_contain not in report.target:
                continue

            if report.timestamp and item.until and report.timestamp >= item.until:
                continue

            if item.report_type and report.report_type != item.report_type:
                continue

            filtered = True

        if not filtered:
            result.append(report)
    return result
