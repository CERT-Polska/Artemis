import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from artemis.reporting.task_handler import handle_single_task


class FakeReportGenerationTask:
    """Minimal stand-in for ReportGenerationTask with configurable attributes."""

    def __init__(
        self,
        tag="default-tag",
        language="en_US",
        custom_template_arguments=None,
        skip_previously_exported=False,
        skip_hooks=False,
        skip_suspicious_reports=False,
        include_only_results_since=None,
        output_location=None,
    ):
        self.tag = tag
        self.language = language
        self.custom_template_arguments = custom_template_arguments or {}
        self.skip_previously_exported = skip_previously_exported
        self.skip_hooks = skip_hooks
        self.skip_suspicious_reports = skip_suspicious_reports
        self.include_only_results_since = include_only_results_since
        self.output_location = output_location


class TestHandleSingleTaskNoVariableShadowing(unittest.TestCase):
    """Regression tests ensuring handle_single_task uses the original task's
    parameters (tag, language, etc.) rather than a shadowed loop variable
    from db.list_report_generation_tasks()."""

    def _create_fake_output_dir(self, tag="some-tag"):
        """Create a temporary directory that mimics a report output with an output.json."""
        output_dir = tempfile.mkdtemp()
        advanced_dir = os.path.join(output_dir, "advanced")
        os.makedirs(advanced_dir, exist_ok=True)
        with open(os.path.join(advanced_dir, "output.json"), "w") as f:
            json.dump({"messages": {}, "alerts": []}, f)
        return output_dir

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_called_with_original_task_params_when_skip_previously_exported(self, mock_db, mock_export):
        """When skip_previously_exported=True, the export() call must use the
        original task's tag/language/etc., NOT the last item from
        db.list_report_generation_tasks()."""

        mock_export.return_value = Path("/tmp/fake-output")

        # The task the operator actually requested
        original_task = FakeReportGenerationTask(
            tag="org-A",
            language="pl_PL",
            custom_template_arguments={"key": "value"},
            skip_previously_exported=True,
            skip_hooks=True,
            skip_suspicious_reports=True,
            include_only_results_since=None,
        )

        # A different task that exists in the DB — this is what the old buggy
        # code would have used after the for-loop shadowed the variable.
        other_output_dir = self._create_fake_output_dir()
        other_task = FakeReportGenerationTask(
            tag="org-B",
            language="en_US",
            custom_template_arguments={},
            skip_previously_exported=False,
            skip_hooks=False,
            skip_suspicious_reports=False,
            output_location=other_output_dir,
        )

        mock_db.list_report_generation_tasks.return_value = [other_task]

        handle_single_task(original_task)

        # Verify export() was called with the ORIGINAL task's parameters
        mock_export.assert_called_once()
        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "org-A")
        self.assertEqual(call_kwargs["language"].value, "pl_PL")
        self.assertEqual(call_kwargs["custom_template_arguments"], {"key": "value"})
        self.assertTrue(call_kwargs["skip_hooks"])
        self.assertTrue(call_kwargs["skip_suspicious_reports"])

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_called_with_original_task_params_multiple_existing_tasks(self, mock_db, mock_export):
        """Same as above but with multiple existing tasks in the DB, ensuring
        the last one doesn't leak into export()."""

        mock_export.return_value = Path("/tmp/fake-output")

        original_task = FakeReportGenerationTask(
            tag="my-target-tag",
            language="en_US",
            skip_previously_exported=True,
            skip_hooks=False,
            skip_suspicious_reports=True,
        )

        existing_tasks = []
        for i in range(3):
            output_dir = self._create_fake_output_dir()
            existing_tasks.append(
                FakeReportGenerationTask(
                    tag=f"wrong-tag-{i}",
                    language="pl_PL",
                    skip_hooks=True,
                    skip_suspicious_reports=False,
                    output_location=output_dir,
                )
            )

        mock_db.list_report_generation_tasks.return_value = existing_tasks

        handle_single_task(original_task)

        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "my-target-tag")
        self.assertFalse(call_kwargs["skip_hooks"])
        self.assertTrue(call_kwargs["skip_suspicious_reports"])

    @patch("artemis.reporting.task_handler.export")
    @patch("artemis.reporting.task_handler.db")
    def test_export_called_correctly_when_skip_previously_exported_false(self, mock_db, mock_export):
        """When skip_previously_exported=False, the loop is never entered and
        the original params should still be used (baseline sanity check)."""

        mock_export.return_value = Path("/tmp/fake-output")

        original_task = FakeReportGenerationTask(
            tag="baseline-tag",
            language="en_US",
            skip_previously_exported=False,
        )

        handle_single_task(original_task)

        mock_db.list_report_generation_tasks.assert_not_called()
        call_kwargs = mock_export.call_args[1]
        self.assertEqual(call_kwargs["tag"], "baseline-tag")


if __name__ == "__main__":
    unittest.main()
