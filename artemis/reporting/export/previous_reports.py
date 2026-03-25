import datetime
import json
import logging
import os
from pathlib import Path
from typing import List

from artemis.reporting.base.report import Report


def load_previous_reports(previous_reports_directory: Path) -> List[Report]:
    if not os.path.isdir(previous_reports_directory):
        raise FileNotFoundError(f"Previous reports directory not found: {previous_reports_directory}")

    previous_reports: List[Report] = []
    for path in previous_reports_directory.glob("**/*.json"):
        try:
            with open(path) as f:
                vulnerability_reports = json.load(f)
        except json.JSONDecodeError:
            logging.exception("Failed to parse previous report file %s, treating as empty", path)
            continue
        for target_data in vulnerability_reports["messages"].values():
            for report in target_data["reports"]:
                report = Report(**report)
                if isinstance(report.timestamp, str):
                    report.timestamp = datetime.datetime.fromisoformat(report.timestamp)
                previous_reports.append(report)
    return previous_reports
