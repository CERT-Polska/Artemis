import datetime
import json
from pathlib import Path
from typing import List

from artemis.reporting.base.report import Report


def load_already_exported_reports(already_exported_reports_directory: Path) -> List[Report]:
    already_exported_reports: List[Report] = []
    for path in already_exported_reports_directory.glob("**/*.json"):
        vulnerability_reports = json.load(open(path))
        for target_data in vulnerability_reports["messages"].values():
            for report in target_data["reports"]:
                report = Report(**report)
                if isinstance(report.timestamp, str):
                    report.timestamp = datetime.datetime.fromisoformat(report.timestamp)
                already_exported_reports.append(report)
    return already_exported_reports
