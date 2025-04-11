import enum
from typing import List


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