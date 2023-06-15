import datetime
import json
import os
from pathlib import Path
from typing import List

from artemis.reporting.base.report import Report


def load_previous_reports(previous_reports_directory: Path) -> List[Report]:
    if not os.path.isdir(previous_reports_directory):
        raise FileNotFoundError(f"Previous reports directory not found: {previous_reports_directory}")

    previous_reports: List[Report] = []
    for path in previous_reports_directory.glob("**/*.json"):
        vulnerability_reports = json.load(open(path))
        for target_data in vulnerability_reports["messages"].values():
            for report in target_data["reports"]:
                report = Report(**report)
                if isinstance(report.timestamp, str):
                    report.timestamp = datetime.datetime.fromisoformat(report.timestamp)
                previous_reports.append(report)
    return previous_reports
