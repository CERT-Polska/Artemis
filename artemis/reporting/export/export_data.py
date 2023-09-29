import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional

from tqdm import tqdm

from artemis.domains import is_domain
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporters import get_all_reporters
from artemis.reporting.export.db import DataLoader
from artemis.reporting.export.deduplication import deduplicate_reports


@dataclass
class SingleTopLevelTargetExportData:
    custom_template_arguments: Dict[str, str]
    top_level_target_is_domain: bool
    top_level_target: str
    contains_type: List[ReportType]
    reports: List[Report]


@dataclass
class ExportData:
    timestamp: datetime.datetime
    tag: Optional[str]
    scanned_top_level_targets: List[str]
    scanned_targets: List[str]
    messages: Dict[str, SingleTopLevelTargetExportData]
    alerts: List[str]


def build_export_data(
    previous_reports: List[Report],
    tag: Optional[str],
    db: DataLoader,
    custom_template_arguments_parsed: Dict[str, str],
    timestamp: datetime.datetime,
) -> ExportData:
    reports = deduplicate_reports(previous_reports, db.reports)

    reports_per_top_level_target: Dict[str, List[Report]] = {}
    for report in tqdm(reports):
        if report.top_level_target not in reports_per_top_level_target:
            reports_per_top_level_target[report.top_level_target] = []
        reports_per_top_level_target[report.top_level_target].append(report)

    alerts = []
    for reporter in get_all_reporters():
        alerts.extend(reporter.get_alerts(reports))

    message_data: Dict[str, SingleTopLevelTargetExportData] = {}

    for top_level_target in reports_per_top_level_target.keys():
        contains_type = set()
        for report in reports_per_top_level_target[top_level_target]:
            contains_type.add(report.report_type)

        reports_per_top_level_target[top_level_target] = sorted(
            reports_per_top_level_target[top_level_target], key=lambda report: (report.report_type, report.target)
        )

        message_data[top_level_target] = SingleTopLevelTargetExportData(
            custom_template_arguments=custom_template_arguments_parsed,
            top_level_target_is_domain=is_domain(top_level_target),
            top_level_target=top_level_target,
            contains_type=sorted(contains_type),
            reports=reports_per_top_level_target[top_level_target],
        )

    return ExportData(
        timestamp=timestamp,
        tag=tag,
        scanned_top_level_targets=list(db.scanned_top_level_targets),
        scanned_targets=list(db.scanned_targets),
        messages=message_data,
        alerts=alerts,
    )
