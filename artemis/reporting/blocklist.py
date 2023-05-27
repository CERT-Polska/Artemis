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


def load_blocklist(file_path: Optional[str]) -> List[BlocklistItem]:
    if file_path:
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
            result = []
            for item in data:
                assert len(set(item.keys()) - {"domain", "until", "report_type"}) == 0
                result.append(
                    BlocklistItem(
                        item["domain"],
                        datetime.datetime.strptime(item["until"], "%Y-%m-%d") if item["until"] else None,
                        ReportType(item["report_type"]) if item["report_type"] else None,
                    )
                )
            return result
    else:
        return []


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
            if is_subdomain(report.top_level_target, item.domain):
                if not report.timestamp or not item.until or report.timestamp < item.until:
                    if not item.report_type or report.report_type == item.report_type:
                        filtered = True
        if not filtered:
            result.append(report)
    return result
