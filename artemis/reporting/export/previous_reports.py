import datetime
import json
import os
from pathlib import Path
from typing import List, Optional

from artemis.reporting.base.report import Report


def load_previous_reports(
    previous_reports_directory: Path, use_only_previous_reports_with_tags: Optional[List[str]]
) -> List[Report]:
    if not os.path.isdir(previous_reports_directory):
        raise FileNotFoundError(f"Previous reports directory not found: {previous_reports_directory}")

    previous_reports: List[Report] = []
    for path in previous_reports_directory.glob("**/*.json"):
        data = json.load(open(path))
        if (
            use_only_previous_reports_with_tags
            and data["tag"] not in use_only_previous_reports_with_tags
        ):
            continue

        for target_data in data["messages"].values():
            for report in target_data["reports"]:
                report = Report(**report)
                if isinstance(report.timestamp, str):
                    report.timestamp = datetime.datetime.fromisoformat(report.timestamp)
                previous_reports.append(report)
    return previous_reports
