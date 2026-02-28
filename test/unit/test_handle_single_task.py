import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional, cast
from unittest.mock import MagicMock, patch

from artemis.db import ReportGenerationTask
from artemis.reporting.task_handler import handle_single_task


class FakeReportGenerationTask:
    """Minimal stand-in for ReportGenerationTask with configurable attributes."""

    def __init__(
        self,
        tag: str = "default-tag",
        language: str = "en_US",
        custom_template_arguments: Optional[dict[str, Any]] = None,
        skip_previously_exported: bool = False,
        skip_hooks: bool = False,
        skip_suspicious_reports: bool = False,
        include_only_results_since: Optional[str] = None,
        output_location: Optional[str] = None,
    ) -> None:
        self.tag = tag
        self.language = language
        self.custom_template_arguments = custom_template_arguments or {}
        self.skip_previously_exported = skip_previously_exported
        self.skip_hooks = skip_hooks
        self.skip_suspicious_reports = skip_suspicious_reports
        self.include_only_results_since = include_only_results_since
        self.output_location = output_location


def _as_task(fake: FakeReportGenerationTask) -> ReportGenerationTask:
    return cast(ReportGenerationTask, fake)


class TestHandleSingleTask(unittest.TestCase):
    """Tests for handle_single_task ensuring export() receives the correct
    task parameters under different configurations."""

    def _create_fake_output_dir(self) -> str:
        """Create a temporary directory that mimics a report output with an output.json."""
        output_dir = tempfile.mkdtemp()
        advanced_dir = os.path.join(output_dir, "advanced")
        os.makedirs(advanced_dir, exist_ok=True)
        with open(os.path.join(advanced_dir, "output.json"), "w") as f:
            json.dump({"messages": {}, "alerts": []}, f)
        return output_dir

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_uses_task_params_when_skip_previously_exported_true(
        self, mock_db: MagicMock, mock_export: MagicMock
    ) -> None:
        """When skip_previously_exported=True and other tasks exist in the DB,
        export() should be called with the current task's parameters."""

        mock_export.return_value = Path("/tmp/fake-output")

        task = FakeReportGenerationTask(
            tag="org-A",
            language="pl_PL",
            custom_template_arguments={"key": "value"},
            skip_previously_exported=True,
            skip_hooks=True,
            skip_suspicious_reports=True,
        )

        other_output_dir = self._create_fake_output_dir()
        other_task = FakeReportGenerationTask(
            tag="org-B",
            language="en_US",
            skip_previously_exported=False,
            skip_hooks=False,
            skip_suspicious_reports=False,
            output_location=other_output_dir,
        )

        mock_db.list_report_generation_tasks.return_value = [other_task]

        handle_single_task(_as_task(task))

        mock_export.assert_called_once()
        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "org-A")
        self.assertEqual(call_kwargs["language"].value, "pl_PL")
        self.assertEqual(call_kwargs["custom_template_arguments"], {"key": "value"})
        self.assertTrue(call_kwargs["skip_hooks"])
        self.assertTrue(call_kwargs["skip_suspicious_reports"])

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_uses_task_params_when_skip_previously_exported_false(
        self, mock_db: MagicMock, mock_export: MagicMock
    ) -> None:
        """When skip_previously_exported=False, export() should be called with
        the task's parameters and no previous reports should be queried."""

        mock_export.return_value = Path("/tmp/fake-output")

        task = FakeReportGenerationTask(
            tag="baseline-tag",
            language="en_US",
            skip_previously_exported=False,
        )

        handle_single_task(_as_task(task))

        mock_db.list_report_generation_tasks.assert_not_called()
        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "baseline-tag")
        self.assertIsNone(call_kwargs["previous_reports_directory"])

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_uses_task_params_when_no_existing_tasks_in_db(
        self, mock_db: MagicMock, mock_export: MagicMock
    ) -> None:
        """When skip_previously_exported=True but the DB has no other tasks,
        export() should still be called with the current task's parameters
        and an empty previous reports directory."""

        mock_export.return_value = Path("/tmp/fake-output")

        task = FakeReportGenerationTask(
            tag="only-task",
            language="pl_PL",
            custom_template_arguments={"foo": "bar"},
            skip_previously_exported=True,
            skip_hooks=False,
            skip_suspicious_reports=True,
        )

        mock_db.list_report_generation_tasks.return_value = []

        handle_single_task(_as_task(task))

        mock_export.assert_called_once()
        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "only-task")
        self.assertEqual(call_kwargs["language"].value, "pl_PL")
        self.assertEqual(call_kwargs["custom_template_arguments"], {"foo": "bar"})
        self.assertFalse(call_kwargs["skip_hooks"])
        self.assertTrue(call_kwargs["skip_suspicious_reports"])
        self.assertIsNotNone(call_kwargs["previous_reports_directory"])


if __name__ == "__main__":
    unittest.main()
