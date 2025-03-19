from typing import Any, ClassVar, Dict, Type, TypeVar, cast

T = TypeVar("T", bound="ModuleConfiguration")


class ModuleConfiguration:
    """
    Base class for all module-specific configurations in Artemis.

    This class provides a standardized interface for module configurations with
    serialization, deserialization, and validation capabilities.

    Attributes:
        enabled (bool): Whether the module is enabled. Defaults to True.
    """

    def __init__(self, enabled: bool = True) -> None:
        """
        Initialize a new ModuleConfiguration instance.

        Args:
            enabled (bool, optional): Whether the module is enabled. Defaults to True.
        """
        self.enabled = enabled

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the configuration to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the configuration.
        """
        return {"enabled": self.enabled}

    @classmethod
    def deserialize(cls: Type[T], config_dict: Dict[str, Any]) -> T:
        """
        Create a configuration instance from a dictionary.

        Args:
            config_dict (Dict[str, Any]): Dictionary representation of the configuration.

        Returns:
            T: An instance of the configuration class.
        """
        return cls(enabled=config_dict.get("enabled", True))

    def validate(self) -> bool:
        """
        Validate that the configuration is valid.

        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        # Base validation just checks if enabled is a boolean
        return isinstance(self.enabled, bool)
