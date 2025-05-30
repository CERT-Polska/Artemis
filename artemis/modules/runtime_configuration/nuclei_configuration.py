#!/usr/bin/env python3
import enum
from typing import Any, Dict, List

from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration


class SeverityThreshold(enum.Enum):
    """
    Enum for Nuclei scanner severity thresholds.

    This allows configuration of what severity levels should be included when scanning.
    """

    CRITICAL_ONLY = "critical_only"
    HIGH_AND_ABOVE = "high_and_above"
    MEDIUM_AND_ABOVE = "medium_and_above"
    LOW_AND_ABOVE = "low_and_above"
    ALL = "all"

    @classmethod
    def get_severity_list(cls, threshold: "SeverityThreshold") -> List[str]:
        """
        Returns a list of severity levels that should be included based on the given threshold.

        Args:
            threshold: The severity threshold to filter by

        Returns:
            A list of severity levels as strings
        """
        if threshold == cls.CRITICAL_ONLY:
            return ["critical"]
        elif threshold == cls.HIGH_AND_ABOVE:
            return ["critical", "high"]
        elif threshold == cls.MEDIUM_AND_ABOVE:
            return ["critical", "high", "medium"]
        elif threshold == cls.LOW_AND_ABOVE:
            return ["critical", "high", "medium", "low"]
        elif threshold == cls.ALL:
            return ["critical", "high", "medium", "low", "info", "unknown"]
        else:
            raise ValueError(f"Unknown severity threshold: {threshold}")


class NucleiConfiguration(ModuleRuntimeConfiguration):
    """
    Configuration for the Nuclei vulnerability scanner.

    This class extends the base ModuleRuntimeConfiguration to add Nuclei-specific
    configuration options.

    Attributes:
        severity_threshold (SeverityThreshold): The minimum severity level to include
            when scanning. Defaults to HIGH_AND_ABOVE.
    """

    def __init__(
        self,
        severity_threshold: SeverityThreshold = SeverityThreshold.HIGH_AND_ABOVE,
    ) -> None:
        """
        Initialize a new NucleiConfiguration instance.

        Args:
            severity_threshold (SeverityThreshold, optional): The minimum severity level
                to include when scanning. Defaults to HIGH_AND_ABOVE.
        """
        super().__init__()
        self.severity_threshold = severity_threshold

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the configuration to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the configuration.
        """
        result = super().serialize()
        result.update({"severity_threshold": self.severity_threshold.value})
        return result

    @classmethod
    def deserialize(cls, config_dict: Dict[str, Any]) -> "NucleiConfiguration":
        """
        Create a configuration instance from a dictionary.

        Args:
            config_dict (Dict[str, Any]): Dictionary representation of the configuration.

        Returns:
            NucleiConfiguration: An instance of the configuration.
        """
        if set(config_dict.keys()) - {"severity_threshold"}:
            raise KeyError(f"Unexpected keys in {config_dict}")

        # Get the severity threshold, converting from string to enum if needed
        severity_threshold_value = config_dict.get("severity_threshold", SeverityThreshold.HIGH_AND_ABOVE.value)
        if isinstance(severity_threshold_value, str):
            severity_threshold = SeverityThreshold(severity_threshold_value)
        else:
            severity_threshold = severity_threshold_value

        return cls(
            severity_threshold=severity_threshold,
        )

    def validate(self) -> bool:
        """
        Validate that the configuration is valid.

        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        base_valid = super().validate()

        # Check if severity_threshold is a valid SeverityThreshold enum value
        severity_valid = isinstance(self.severity_threshold, SeverityThreshold)

        return base_valid and severity_valid

    def get_severity_options(self) -> List[str]:
        """
        Get a list of severity levels based on the configured threshold.

        Returns:
            List[str]: A list of severity levels (e.g., ["critical", "high"]).
        """
        return SeverityThreshold.get_severity_list(self.severity_threshold)
