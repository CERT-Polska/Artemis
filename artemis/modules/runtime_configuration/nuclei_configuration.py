#!/usr/bin/env python3
from typing import Any, Dict, List

from artemis.module_configurations.nuclei import SeverityThreshold
from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration


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
