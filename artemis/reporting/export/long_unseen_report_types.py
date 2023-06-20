import datetime
from typing import List

from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType


def print_long_unseen_report_types(reports: List[Report], threshold_days: int = 20) -> None:
    """Prints report types that have not been observed in last threshold_days days.

    This is to detect a situation where a report type stops being generated due to a bug.
    """
    last_seen = {}

    for report in reports:
        if not report.timestamp:
            continue

        if report.report_type not in last_seen:
            last_seen[report.report_type] = report.timestamp
        elif report.timestamp > last_seen[report.report_type]:
            last_seen[report.report_type] = report.timestamp

    errors = []
    for report_type in sorted(ReportType.get_all()):
        if report_type not in last_seen:
            errors.append(f"{report_type}: never seen")
        elif last_seen[report_type] < datetime.datetime.now() - datetime.timedelta(days=threshold_days):
            errors.append(f"{report_type}: last seen {last_seen[report_type]}")

    if errors:
        print("Some report types have not been observed for a long time:")
        for error in errors:
            print("\t" + error)
