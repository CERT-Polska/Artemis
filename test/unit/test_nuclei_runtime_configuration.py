#!/usr/bin/env python3
import unittest
from typing import Any, Dict

from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)


class TestNucleiConfiguration(unittest.TestCase):
    """Test suite for the NucleiConfiguration class."""

    def test_init_with_default_values(self) -> None:
        """Test initialization with default values."""
        config = NucleiConfiguration()
        self.assertEqual(config.severity_threshold, SeverityThreshold.HIGH_AND_ABOVE)

    def test_init_with_custom_values(self) -> None:
        """Test initialization with custom values."""
        config = NucleiConfiguration(severity_threshold=SeverityThreshold.MEDIUM_AND_ABOVE)
        self.assertEqual(config.severity_threshold, SeverityThreshold.MEDIUM_AND_ABOVE)

    def test_serialize(self) -> None:
        """Test serialization to dictionary."""
        config = NucleiConfiguration(severity_threshold=SeverityThreshold.LOW_AND_ABOVE)
        serialized = config.serialize()

        self.assertIsInstance(serialized, dict)
        self.assertEqual(serialized["severity_threshold"], "low_and_above")

    def test_serialize_with_defaults(self) -> None:
        """Test serialization with default values."""
        config = NucleiConfiguration()
        serialized = config.serialize()

        self.assertEqual(serialized["severity_threshold"], "high_and_above")

    def test_deserialize(self) -> None:
        """Test deserialization from dictionary."""
        config_dict: Dict[str, Any] = {"severity_threshold": "low_and_above"}
        config = NucleiConfiguration.deserialize(config_dict)

        self.assertIsInstance(config, NucleiConfiguration)
        self.assertEqual(config.severity_threshold, SeverityThreshold.LOW_AND_ABOVE)

    def test_deserialize_with_enum_value(self) -> None:
        """Test deserialization with an actual enum value instead of string."""
        config_dict: Dict[str, Any] = {
            "severity_threshold": SeverityThreshold.CRITICAL_ONLY,
        }
        config = NucleiConfiguration.deserialize(config_dict)

        self.assertEqual(config.severity_threshold, SeverityThreshold.CRITICAL_ONLY)

    def test_deserialize_with_missing_values(self) -> None:
        """Test deserialization with missing values."""
        config_dict: Dict[str, Any] = {}
        config = NucleiConfiguration.deserialize(config_dict)

        self.assertEqual(config.severity_threshold, SeverityThreshold.HIGH_AND_ABOVE)

    def test_validate_valid_config(self) -> None:
        """Test validation with valid configuration."""
        config = NucleiConfiguration(severity_threshold=SeverityThreshold.ALL)
        self.assertTrue(config.validate())

    def test_validate_invalid_severity(self) -> None:
        """Test validation with invalid severity threshold."""
        config = NucleiConfiguration()
        # Manually set an invalid value to test validation
        config.severity_threshold = "invalid"  # type: ignore
        self.assertFalse(config.validate())

    def test_get_severity_options(self) -> None:
        """Test get_severity_options method for different thresholds."""
        # Test CRITICAL_ONLY
        config1 = NucleiConfiguration(severity_threshold=SeverityThreshold.CRITICAL_ONLY)
        self.assertEqual(config1.get_severity_options(), ["critical"])

        # Test HIGH_AND_ABOVE
        config2 = NucleiConfiguration(severity_threshold=SeverityThreshold.HIGH_AND_ABOVE)
        self.assertEqual(config2.get_severity_options(), ["critical", "high"])

        # Test MEDIUM_AND_ABOVE
        config3 = NucleiConfiguration(severity_threshold=SeverityThreshold.MEDIUM_AND_ABOVE)
        self.assertEqual(config3.get_severity_options(), ["critical", "high", "medium"])

        # Test LOW_AND_ABOVE
        config4 = NucleiConfiguration(severity_threshold=SeverityThreshold.LOW_AND_ABOVE)
        self.assertEqual(config4.get_severity_options(), ["critical", "high", "medium", "low"])

        # Test ALL
        config5 = NucleiConfiguration(severity_threshold=SeverityThreshold.ALL)
        self.assertEqual(config5.get_severity_options(), ["critical", "high", "medium", "low", "info", "unknown"])


if __name__ == "__main__":
    unittest.main()
