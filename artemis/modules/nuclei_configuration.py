#!/usr/bin/env python3
from typing import Any, Dict, List, Optional

from artemis.module_configurations.nuclei import SeverityThreshold
from artemis.modules.base.module_configuration import ModuleConfiguration


class NucleiConfiguration(ModuleConfiguration):
    """
    Configuration for the Nuclei vulnerability scanner.

    This class extends the base ModuleConfiguration to add Nuclei-specific
    configuration options.

    Attributes:
        severity_threshold (SeverityThreshold): The minimum severity level to include
            when scanning. Defaults to MEDIUM_AND_ABOVE.
        max_templates (Optional[int]): The maximum number of templates to use. Defaults to None.
    """

    def __init__(
        self,
        severity_threshold: SeverityThreshold = SeverityThreshold.MEDIUM_AND_ABOVE,
        max_templates: int = None,
    ) -> None:
        """
        Initialize a new NucleiConfiguration instance.

        Args:
            severity_threshold (SeverityThreshold, optional): The minimum severity level
                to include when scanning. Defaults to MEDIUM_AND_ABOVE.
            max_templates (Optional[int], optional): The maximum number of templates to use. Defaults to None.
        """
        super().__init__()
        self.severity_threshold = severity_threshold
        self.max_templates = max_templates

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the configuration to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the configuration.
        """
        result = super().serialize()
        result.update({"severity_threshold": self.severity_threshold.value})
        if self.max_templates is not None:
            result["max_templates"] = self.max_templates
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
        severity_threshold_value = config_dict.get("severity_threshold", SeverityThreshold.MEDIUM_AND_ABOVE.value)
        if isinstance(severity_threshold_value, str):
            severity_threshold = SeverityThreshold(severity_threshold_value)
        else:
            severity_threshold = severity_threshold_value
        max_templates = config_dict.get("max_templates")

        return cls(
            severity_threshold=severity_threshold,
            max_templates=max_templates,
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

        # Check if max_templates is a valid integer and greater than 0
        max_templates_valid = (
            self.max_templates is None or (isinstance(self.max_templates, int) and self.max_templates > 0)
        )

        return base_valid and severity_valid and max_templates_valid

    def get_severity_options(self) -> List[str]:
        """
        Get a list of severity levels based on the configured threshold.

        Returns:
            List[str]: A list of severity levels (e.g., ["critical", "high"]).
        """
        return SeverityThreshold.get_severity_list(self.severity_threshold)
