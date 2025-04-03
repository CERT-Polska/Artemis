import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional

from artemis.domains import is_domain
from artemis.reporting.base.language import Language
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
    language: str
    scanned_top_level_targets: List[str]
    scanned_targets: List[str]
    ips: Dict[str, List[str]]
    messages: Dict[str, SingleTopLevelTargetExportData]
    alerts: List[str]
    hosts_with_waf_detected: List[str]


def build_export_data(
    previous_reports: List[Report],
    tag: Optional[str],
    language: Language,
    db: DataLoader,
    custom_template_arguments_parsed: Dict[str, str],
    timestamp: datetime.datetime,
    skip_suspicious_reports: bool,
) -> ExportData:
    reports = deduplicate_reports(previous_reports, db.reports)

    reports_per_top_level_target: Dict[str, List[Report]] = {}
    for report in reports:
        if report.top_level_target not in reports_per_top_level_target:
            reports_per_top_level_target[report.top_level_target] = []
        reports_per_top_level_target[report.top_level_target].append(report)

    alerts = []
    for reporter in get_all_reporters():
        alerts.extend(reporter.get_alerts(reports))

    for top_level_target in list(reports_per_top_level_target.keys()):
        reports_per_top_level_target[top_level_target] = [
            report
            for report in reports_per_top_level_target[top_level_target]
            if not report.is_suspicious or not skip_suspicious_reports
        ]
        if len(reports_per_top_level_target[top_level_target]) == 0:
            del reports_per_top_level_target[top_level_target]

    message_data: Dict[str, SingleTopLevelTargetExportData] = {}

    for operator_name, operator in [("min", min), ("max", max)]:
        custom_template_arguments_parsed[operator_name + "_vulnerability_date_str"] = (
            datetime.datetime.strftime(  # type: ignore
                operator([report.timestamp for report in reports if report.timestamp]),
                "%Y-%m-%d",
            )
            if reports
            else None
        )

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
        language=language.value,
        scanned_top_level_targets=list(db.scanned_top_level_targets),
        scanned_targets=list(db.scanned_targets),
        ips=db.ips,
        messages=message_data,
        alerts=alerts,
        hosts_with_waf_detected=list(db.hosts_with_waf_detected),
    )
