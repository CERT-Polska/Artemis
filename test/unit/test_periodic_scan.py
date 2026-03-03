import datetime
import sys
import unittest
from unittest.mock import MagicMock, patch

from artemis.db import PeriodicScan


class TestPeriodicScanModel(unittest.TestCase):
    def test_periodic_scan_table_name(self) -> None:
        self.assertEqual(PeriodicScan.__tablename__, "periodic_scan")

    def test_periodic_scan_columns(self) -> None:
        column_names = {col.name for col in PeriodicScan.__table__.columns}
        expected = {
            "id",
            "targets",
            "tag",
            "disabled_modules",
            "interval_hours",
            "priority",
            "enabled",
            "last_run_at",
            "next_run_at",
            "created_at",
        }
        self.assertEqual(column_names, expected)

    def test_periodic_scan_id_is_primary_key(self) -> None:
        self.assertTrue(PeriodicScan.__table__.columns["id"].primary_key)

    def test_periodic_scan_targets_not_nullable(self) -> None:
        self.assertFalse(PeriodicScan.__table__.columns["targets"].nullable)

    def test_periodic_scan_interval_not_nullable(self) -> None:
        self.assertFalse(PeriodicScan.__table__.columns["interval_hours"].nullable)

    def test_periodic_scan_enabled_not_nullable(self) -> None:
        self.assertFalse(PeriodicScan.__table__.columns["enabled"].nullable)

    def test_periodic_scan_tag_nullable(self) -> None:
        self.assertTrue(PeriodicScan.__table__.columns["tag"].nullable)

    def test_periodic_scan_last_run_at_nullable(self) -> None:
        self.assertTrue(PeriodicScan.__table__.columns["last_run_at"].nullable)


class TestPeriodicScanScheduler(unittest.TestCase):
    """Tests for the periodic scan scheduler logic.

    artemis.producer creates a Karton Producer at module level, which requires
    S3/Redis infrastructure. We mock it at sys.modules level before importing
    the scheduler module.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._mock_producer_module = MagicMock()
        cls._mock_producer_module.create_tasks = MagicMock(return_value=[])
        sys.modules.setdefault("artemis.producer", cls._mock_producer_module)

        if "artemis.periodic_scan_scheduler" in sys.modules:
            del sys.modules["artemis.periodic_scan_scheduler"]

    def setUp(self) -> None:
        self._mock_producer_module.create_tasks.reset_mock()

    def _get_scheduler_module(self) -> MagicMock:
        import artemis.periodic_scan_scheduler as scheduler_mod

        return scheduler_mod  # type: ignore

    def test_run_due_periodic_scans_no_due_scans(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = []

        scheduler.run_due_periodic_scans()

        self._mock_producer_module.create_tasks.assert_not_called()
        scheduler.db.mark_periodic_scan_as_run.assert_not_called()

    def test_run_due_periodic_scans_with_due_scan(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 1,
                "targets": "example.com\nexample.org",
                "tag": "test-tag",
                "disabled_modules": "bruter,nuclei",
                "interval_hours": 24,
                "priority": "normal",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            }
        ]
        self._mock_producer_module.create_tasks.return_value = ["task-id-1", "task-id-2"]

        scheduler.run_due_periodic_scans()

        self._mock_producer_module.create_tasks.assert_called_once()
        call_args = self._mock_producer_module.create_tasks.call_args
        self.assertEqual(sorted(call_args[0][0]), ["example.com", "example.org"])
        self.assertEqual(call_args[0][1], "test-tag")
        self.assertEqual(sorted(call_args[1]["disabled_modules"]), ["bruter", "nuclei"])
        scheduler.db.mark_periodic_scan_as_run.assert_called_once_with(1)

    def test_run_due_periodic_scans_empty_disabled_modules(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 2,
                "targets": "10.0.0.1",
                "tag": None,
                "disabled_modules": "",
                "interval_hours": 12,
                "priority": "high",
                "enabled": True,
                "last_run_at": datetime.datetime(2026, 1, 1),
                "next_run_at": datetime.datetime(2026, 1, 1, 12),
            }
        ]
        self._mock_producer_module.create_tasks.return_value = ["task-id-1"]

        scheduler.run_due_periodic_scans()

        call_args = self._mock_producer_module.create_tasks.call_args
        self.assertEqual(call_args[0][0], ["10.0.0.1"])
        self.assertIsNone(call_args[0][1])
        self.assertEqual(call_args[1]["disabled_modules"], [])

    def test_run_due_scan_marks_as_run_even_on_create_tasks_error(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 3,
                "targets": "example.com",
                "tag": None,
                "disabled_modules": "",
                "interval_hours": 24,
                "priority": "normal",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            }
        ]
        self._mock_producer_module.create_tasks.side_effect = Exception("connection failed")

        scheduler.run_due_periodic_scans()

        scheduler.db.mark_periodic_scan_as_run.assert_called_once_with(3)

    def test_run_due_periodic_scans_multiple_scans(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 10,
                "targets": "a.com",
                "tag": "tag-a",
                "disabled_modules": "",
                "interval_hours": 6,
                "priority": "normal",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            },
            {
                "id": 20,
                "targets": "b.com",
                "tag": "tag-b",
                "disabled_modules": "nuclei",
                "interval_hours": 12,
                "priority": "high",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            },
        ]
        self._mock_producer_module.create_tasks.return_value = ["id1"]

        scheduler.run_due_periodic_scans()

        self.assertEqual(self._mock_producer_module.create_tasks.call_count, 2)
        self.assertEqual(scheduler.db.mark_periodic_scan_as_run.call_count, 2)
        scheduler.db.mark_periodic_scan_as_run.assert_any_call(10)
        scheduler.db.mark_periodic_scan_as_run.assert_any_call(20)

    def test_targets_are_stripped(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 5,
                "targets": "  example.com  \n  example.org  \n",
                "tag": None,
                "disabled_modules": "",
                "interval_hours": 24,
                "priority": "normal",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            }
        ]
        self._mock_producer_module.create_tasks.return_value = ["id1"]

        scheduler.run_due_periodic_scans()

        call_args = self._mock_producer_module.create_tasks.call_args
        self.assertEqual(sorted(call_args[0][0]), ["example.com", "example.org"])

    def test_empty_lines_in_targets_are_skipped(self) -> None:
        scheduler = self._get_scheduler_module()
        scheduler.db = MagicMock()
        scheduler.db.get_due_periodic_scans.return_value = [
            {
                "id": 6,
                "targets": "example.com\n\n\nexample.org\n\n",
                "tag": None,
                "disabled_modules": "",
                "interval_hours": 24,
                "priority": "normal",
                "enabled": True,
                "last_run_at": None,
                "next_run_at": datetime.datetime(2026, 1, 1),
            }
        ]
        self._mock_producer_module.create_tasks.return_value = ["id1"]

        scheduler.run_due_periodic_scans()

        call_args = self._mock_producer_module.create_tasks.call_args
        self.assertEqual(sorted(call_args[0][0]), ["example.com", "example.org"])


if __name__ == "__main__":
    unittest.main()
