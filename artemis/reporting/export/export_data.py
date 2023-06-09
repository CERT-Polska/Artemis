from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from tqdm import tqdm

from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.export.db import ExportDBConnector
from artemis.reporting.export.deduplication import (
    deduplicate_ip_vs_domain_versions,
    deduplicate_reports_choosing_ones_with_best_scores,
)
from artemis.utils import is_ip_address


@dataclass
class SingleTopLevelTargetExportData:
    custom_template_arguments: Dict[str, str]
    top_level_target_is_ip_address: bool
    top_level_target: str
    contains_type: List[ReportType]
    reports: List[Report]


@dataclass
class ExportData:
    tag: Optional[str]
    scanned_top_level_targets: List[str]
    scanned_targets: List[str]
    messages: Dict[str, SingleTopLevelTargetExportData]
    num_reports_per_type: Dict[ReportType, int]


def build_export_data(
    already_exported_reports: List[Report],
    tag: Optional[str],
    db: ExportDBConnector,
    custom_template_arguments_parsed: Dict[str, str],
) -> ExportData:
    reports = deduplicate_reports_choosing_ones_with_best_scores(already_exported_reports, db.reports)
    reports = deduplicate_ip_vs_domain_versions(already_exported_reports, reports)

    reports_per_top_level_target: Dict[str, List[Report]] = {}
    for report in tqdm(reports):
        if report.top_level_target not in reports_per_top_level_target:
            reports_per_top_level_target[report.top_level_target] = []
        reports_per_top_level_target[report.top_level_target].append(report)

    message_data: Dict[str, SingleTopLevelTargetExportData] = {}
    num_reports_per_type: Counter[ReportType] = Counter()

    for top_level_target in reports_per_top_level_target.keys():
        contains_type = set()
        for report in reports_per_top_level_target[top_level_target]:
            contains_type.add(report.report_type)

        num_reports_per_type.update([report.report_type for report in reports_per_top_level_target[top_level_target]])

        reports_per_top_level_target[top_level_target] = sorted(
            reports_per_top_level_target[top_level_target], key=lambda report: (report.report_type, report.target)
        )

        message_data[top_level_target] = SingleTopLevelTargetExportData(
            custom_template_arguments=custom_template_arguments_parsed,
            top_level_target_is_ip_address=is_ip_address(top_level_target),
            top_level_target=top_level_target,
            contains_type=sorted(contains_type),
            reports=reports_per_top_level_target[top_level_target],
        )

    return ExportData(
        tag=tag,
        scanned_top_level_targets=list(db.scanned_top_level_targets),
        scanned_targets=list(db.scanned_targets),
        messages=message_data,
        num_reports_per_type=dict(num_reports_per_type),
    )
