import collections
import copy
import datetime
from typing import Any, DefaultDict, List, Set

from artemis.config import Config
from artemis.reporting.base.report import Report
from artemis.reporting.severity import SEVERITY_MAP, Severity


def deduplicate_ip_vs_domain_versions(previous_reports: List[Report], reports_to_send: List[Report]) -> List[Report]:
    """Skips reports if:

    - a vulnerability is on a URL with an IP and an identical report for a domain with this IP has
      already been sent,
    - a vulnerability is on a URL with an IP and an identical report for a domain with this IP is
      planned to be sent,
    - a vulnerability is on a URL with a domain and an identical report for a URL with an IP of this domain has
      already been sent.
    """
    previous_reports_by_ip_normal_forms: DefaultDict[Any, Any] = collections.defaultdict(list)
    previous_reports_by_normal_forms: DefaultDict[Any, Any] = collections.defaultdict(list)
    for previous_report in previous_reports:
        previous_reports_by_normal_forms[previous_report.get_normal_form()].append(previous_report)
        alternative_with_ip_address = previous_report.alternative_with_ip_address()
        if alternative_with_ip_address:
            previous_reports_by_ip_normal_forms[alternative_with_ip_address.get_normal_form()].append(
                alternative_with_ip_address
            )

    reports_to_send_ip_normal_forms: Set[Any] = set()
    for report in reports_to_send:
        if not report.target_is_ip_address():
            alternative_with_ip_address = report.alternative_with_ip_address()
            if alternative_with_ip_address:
                reports_to_send_ip_normal_forms.add(alternative_with_ip_address.get_normal_form())

    reports_to_send_filtered: List[Report] = []
    for report in reports_to_send:
        # This is an IP report and is an ip-converted version of an existing report
        if report.target_is_ip_address() and report.get_normal_form() in previous_reports_by_ip_normal_forms:
            if _all_reports_are_old(previous_reports_by_ip_normal_forms[report.get_normal_form()]):
                reports_to_send_filtered.append(_build_subsequent_reminder(report))
            continue
        # This is not an IP report but an IP report for the same has already been sent
        if not report.target_is_ip_address():
            alternative_with_ip_address = report.alternative_with_ip_address()
            if (
                alternative_with_ip_address
                and alternative_with_ip_address.get_normal_form() in previous_reports_by_normal_forms
            ):
                if _all_reports_are_old(
                    previous_reports_by_normal_forms[alternative_with_ip_address.get_normal_form()]
                ):
                    reports_to_send_filtered.append(_build_subsequent_reminder(report))
                continue
        # This is an IP report but we have a non-ip version to send
        if report.target_is_ip_address() and report.get_normal_form() in reports_to_send_ip_normal_forms:
            continue
        reports_to_send_filtered.append(report)
    return reports_to_send_filtered


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
