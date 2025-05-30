#!/usr/bin/env python3
import unittest

from artemis.modules.runtime_configuration.nuclei_configuration import SeverityThreshold


class TestSeverityThreshold(unittest.TestCase):
    """Test suite for the SeverityThreshold enum."""

    def test_enum_values(self) -> None:
        """Test that the enum contains all expected values."""
        self.assertEqual(SeverityThreshold.CRITICAL_ONLY.value, "critical_only")
        self.assertEqual(SeverityThreshold.HIGH_AND_ABOVE.value, "high_and_above")
        self.assertEqual(SeverityThreshold.MEDIUM_AND_ABOVE.value, "medium_and_above")
        self.assertEqual(SeverityThreshold.LOW_AND_ABOVE.value, "low_and_above")
        self.assertEqual(SeverityThreshold.ALL.value, "all")

    def test_get_severity_list_critical_only(self) -> None:
        """Test that get_severity_list returns only critical for CRITICAL_ONLY."""
        severity_list = SeverityThreshold.get_severity_list(SeverityThreshold.CRITICAL_ONLY)
        self.assertEqual(severity_list, ["critical"])

    def test_get_severity_list_high_and_above(self) -> None:
        """Test that get_severity_list returns critical and high for HIGH_AND_ABOVE."""
        severity_list = SeverityThreshold.get_severity_list(SeverityThreshold.HIGH_AND_ABOVE)
        self.assertEqual(severity_list, ["critical", "high"])

    def test_get_severity_list_medium_and_above(self) -> None:
        """Test that get_severity_list returns critical, high, and medium for MEDIUM_AND_ABOVE."""
        severity_list = SeverityThreshold.get_severity_list(SeverityThreshold.MEDIUM_AND_ABOVE)
        self.assertEqual(severity_list, ["critical", "high", "medium"])

    def test_get_severity_list_low_and_above(self) -> None:
        """Test that get_severity_list returns critical, high, medium, and low for LOW_AND_ABOVE."""
        severity_list = SeverityThreshold.get_severity_list(SeverityThreshold.LOW_AND_ABOVE)
        self.assertEqual(severity_list, ["critical", "high", "medium", "low"])

    def test_get_severity_list_all(self) -> None:
        """Test that get_severity_list returns all severity levels for ALL."""
        severity_list = SeverityThreshold.get_severity_list(SeverityThreshold.ALL)
        self.assertEqual(severity_list, ["critical", "high", "medium", "low", "info", "unknown"])

    def test_get_severity_list_invalid(self) -> None:
        """Test that get_severity_list raises ValueError for invalid threshold."""
        with self.assertRaises(ValueError):
            # Using a string instead of a SeverityThreshold enum value
            SeverityThreshold.get_severity_list("invalid")  # type: ignore


if __name__ == "__main__":
    unittest.main()
