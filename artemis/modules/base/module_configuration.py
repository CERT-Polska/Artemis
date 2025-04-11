from typing import Any, ClassVar, Dict, Type, TypeVar, cast

T = TypeVar("T", bound="ModuleConfiguration")


class ModuleConfiguration:
    """
    Base class for all module-specific configurations in Artemis.

    This class provides a standardized interface for module configurations with
    serialization, deserialization, and validation capabilities.
    
    Note: Module enabling/disabling is handled separately through the API's
    disabled_modules parameter, not through this configuration class.
    """

    def __init__(self) -> None:
        """
        Initialize a new ModuleConfiguration instance.
        """
        pass

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the configuration to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the configuration.
        """
        return {}

    @classmethod
    def deserialize(cls: Type[T], config_dict: Dict[str, Any]) -> T:
        """
        Create a configuration instance from a dictionary.

        Args:
            config_dict (Dict[str, Any]): Dictionary representation of the configuration.

        Returns:
            T: An instance of the configuration class.
        """
        return cls()

    def validate(self) -> bool:
        """
        Validate that the configuration is valid.

        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        # Base implementation always returns True since there are no attributes to validate
        return True
