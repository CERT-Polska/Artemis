import collections
import copy
import dataclasses
import datetime
from typing import Any, DefaultDict, List

from artemis.config import Config
from artemis.reporting.base.normal_form import NormalForm
from artemis.reporting.base.report import Report
from artemis.reporting.severity import SEVERITY_MAP, Severity


@dataclasses.dataclass
class ReportsByNormalForms:
    by_normal_forms: DefaultDict[NormalForm, List[Report]]

    # If a report is about a URL where the host is a domain, not an IP, by_alternative_ip_normal_forms
    # will contain the normal form of a version of this report where the domain is replaced with an IP.

    # Such an alternative vulnerability doesn't necessairly have to exist. There is plenty of cases
    # where vulnerability exists only by domain, not by IP. The purpose of this method is to return a
    # potential IP version for deduplication.
    by_alternative_ip_normal_forms: DefaultDict[NormalForm, List[Report]]

    @staticmethod
    def from_reports(reports: List[Report]) -> "ReportsByNormalForms":
        by_alternative_ip_normal_forms: DefaultDict[NormalForm, List[Report]] = collections.defaultdict(list)
        by_normal_forms: DefaultDict[NormalForm, List[Report]] = collections.defaultdict(list)
        for report in reports:
            by_normal_forms[report.get_normal_form()].append(report)
            alternative_with_ip_address = report.alternative_with_ip_address()
            if alternative_with_ip_address:
                by_alternative_ip_normal_forms[alternative_with_ip_address.get_normal_form()].append(
                    alternative_with_ip_address
                )
        return ReportsByNormalForms(
            by_normal_forms=by_normal_forms, by_alternative_ip_normal_forms=by_alternative_ip_normal_forms
        )


def deduplicate_ip_vs_domain_versions(previous_reports: List[Report], reports_to_send: List[Report]) -> List[Report]:
    """Skips reports if:

    - a vulnerability is on a URL with an IP and an identical report for a domain with this IP has
      already been sent,
    - a vulnerability is on a URL with an IP and an identical report for a domain with this IP is
      planned to be sent,
    - a vulnerability is on a URL with a domain and an identical report for a URL with an IP of this domain has
      already been sent.
    """

    previous_reports_normalized = ReportsByNormalForms.from_reports(previous_reports)
    reports_normalized = ReportsByNormalForms.from_reports(reports_to_send)
    filtered_reports: List[Report] = []

    def _process_ip_report(processed_report: Report) -> None:
        if processed_report.get_normal_form() in previous_reports_normalized.by_alternative_ip_normal_forms:
            # This is an ip-converted version of an existing report
            if _all_reports_are_old(
                previous_reports_normalized.by_alternative_ip_normal_forms[processed_report.get_normal_form()]
            ):
                filtered_reports.append(_build_subsequent_reminder(processed_report))
            return

        if processed_report.get_normal_form() in reports_normalized.by_alternative_ip_normal_forms:
            # This is an IP report, but we have a non-ip version to send
            return
        filtered_reports.append(processed_report)

    def _process_non_ip_report(processed_report: Report) -> None:
        alternative_with_ip_address = processed_report.alternative_with_ip_address()
        if (
            alternative_with_ip_address
            and alternative_with_ip_address.get_normal_form() in previous_reports_normalized.by_normal_forms
        ):
            # This is not an IP report but an IP report for the same has already been sent
            if _all_reports_are_old(
                previous_reports_normalized.by_normal_forms[alternative_with_ip_address.get_normal_form()]
            ):
                filtered_reports.append(_build_subsequent_reminder(processed_report))
            return
        filtered_reports.append(processed_report)

    for report in reports_to_send:
        if report.target_is_ip_address():
            _process_ip_report(report)
        else:
            _process_non_ip_report(report)

    return filtered_reports


def deduplicate_reports(previous_reports: List[Report], reports_to_send: List[Report]) -> List[Report]:
    previous_reports_by_normal_forms: DefaultDict[Any, Any] = collections.defaultdict(list)
    for report in previous_reports:
        report_normal_form = report.get_normal_form()
        previous_reports_by_normal_forms[report_normal_form].append(report)

    reports_scoring_dict = {}
    for report in reports_to_send:
        report_normal_form = report.get_normal_form()

        if report_normal_form in previous_reports_by_normal_forms:
            if _all_reports_are_old(previous_reports_by_normal_forms[report_normal_form]):
                reports_scoring_dict[report_normal_form] = _build_subsequent_reminder(
                    report,
                )
            continue

        if report_normal_form not in reports_scoring_dict:
            reports_scoring_dict[report_normal_form] = report
        elif reports_scoring_dict[report_normal_form].get_score() < report.get_score():
            reports_scoring_dict[report_normal_form] = report

    return list(reports_scoring_dict.values())


def _all_reports_are_old(reports: List[Report]) -> bool:
    for report in reports:
        if SEVERITY_MAP[report.report_type] == Severity.LOW:
            threshold_days = Config.MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW
        elif SEVERITY_MAP[report.report_type] == Severity.MEDIUM:
            threshold_days = Config.MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_MEDIUM
        elif SEVERITY_MAP[report.report_type] == Severity.HIGH:
            threshold_days = Config.MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_HIGH
        else:
            assert False

        if report.timestamp and report.timestamp >= datetime.datetime.now() - datetime.timedelta(days=threshold_days):
            return False
    return True


def _build_subsequent_reminder(report: Report) -> Report:
    new_report = copy.deepcopy(report)
    new_report.is_subsequent_reminder = True
    return new_report
