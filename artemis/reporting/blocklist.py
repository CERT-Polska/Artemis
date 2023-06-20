import dataclasses
import datetime
from typing import List, Optional

import yaml

from artemis.domains import is_subdomain
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType


@dataclasses.dataclass
class BlocklistItem:
    domain: str
    until: Optional[datetime.datetime]
    report_type: Optional[ReportType]


class BlocklistError(Exception):
    pass


def load_blocklist(file_path: Optional[str]) -> List[BlocklistItem]:
    if not file_path:
        return []

    with open(file_path, "r") as file:
        data = yaml.safe_load(file)

    for item in data:
        # Assert there are no additional or missing keys
        if set(item.keys()) != {"domain", "until", "report_type"}:
            raise BlocklistError(f"Expected three keys in entry: domain, until and report_type, not {item.keys()}")

    blocklist_items = [
        BlocklistItem(
            domain=item["domain"],
            until=datetime.datetime.strptime(item["until"], "%Y-%m-%d") if item["until"] else None,
            report_type=item["report_type"] if item["report_type"] else None,
        )
        for item in data
    ]

    return blocklist_items


def filter_blocklist(reports: List[Report], blocklist: List[BlocklistItem]) -> List[Report]:
    result = []
    for report in reports:
        filtered = False
        # each BlocklistItem is a filter that:
        # - refers to only a domain and its subdomains,
        # - if `until` is set, filters only reports earlier than a given date,
        # - if `report_type` is set, filters only reports with given type.
        # If at least one filter matches, report is skipped.
        for item in blocklist:
            if not is_subdomain(report.top_level_target, item.domain):
                continue

            if report.timestamp and item.until and report.timestamp >= item.until:
                continue

            if item.report_type and report.report_type != item.report_type:
                continue

            filtered = True

        if not filtered:
            result.append(report)
    return result
