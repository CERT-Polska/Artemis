import datetime
import unittest
from typing import List
from unittest.mock import patch

from artemis.config import Config
from artemis.reporting.base.normal_form import (
    NormalForm,
    get_url_normal_form,
    get_url_score,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.export.deduplication import deduplicate_reports


class ScoredReport(Report):
    def get_normal_form(self) -> NormalForm:
        return (("type", self.report_type), ("target", get_url_normal_form(self.target)))

    def get_score(self) -> List[int]:
        return [get_url_score(self.target)]


class TestReminderReportScoring(unittest.TestCase):
    def make_report(self, target: str, age_days: int = 0) -> Report:
        return ScoredReport(
            top_level_target="example.org",
            target=target,
            report_type=ReportType("test_report"),
            timestamp=datetime.datetime(2026, 1, 20) - datetime.timedelta(days=age_days),
            target_ip_checked=True,
        )

    def test_highest_score_wins_with_and_without_previous_report(self) -> None:
        best = self.make_report("https://example.org/path")
        worse = self.make_report("http://www.example.org/path")
        old = self.make_report("http://example.org/path", age_days=10)
        with patch.object(Config.Reporting, "MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW", 7):
            for previous in ([], [old]):
                for current in ([best, worse], [worse, best]):
                    with self.subTest(previous=bool(previous), first=current[0].target):
                        result = deduplicate_reports(previous, current)
                        self.assertEqual(len(result), 1)
                        self.assertEqual(result[0].target, best.target)
                        self.assertEqual(result[0].is_subsequent_reminder, bool(previous))
        self.assertFalse(best.is_subsequent_reminder)

    def test_recent_report_still_suppresses_reminders(self) -> None:
        recent = self.make_report("http://example.org/path", age_days=1)
        best = self.make_report("https://example.org/path")
        with patch.object(Config.Reporting, "MIN_DAYS_BETWEEN_REMINDERS__SEVERITY_LOW", 7):
            self.assertEqual(deduplicate_reports([recent], [best]), [])
