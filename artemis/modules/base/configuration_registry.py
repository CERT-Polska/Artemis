from typing import Dict, Optional, Type

from artemis.modules.base.module_configuration import ModuleConfiguration


class ConfigurationRegistry:
    """
    Singleton registry for managing module configurations in Artemis.

    This class maintains a mapping between module names and their
    configuration classes, allowing for centralized configuration management.
    """

    # Singleton instance
    _instance = None

    # Private constructor
    def __new__(cls):
        """Create a singleton instance if one doesn't exist."""
        if cls._instance is None:
            cls._instance = super(ConfigurationRegistry, cls).__new__(cls)
            cls._instance._config_classes: Dict[str, Type[ModuleConfiguration]] = {}
        return cls._instance

    def register_configuration(self, module_name: str, config_class: Type[ModuleConfiguration]) -> None:
        """
        Register a configuration class for a module.

        Args:
            module_name (str): The name of the module.
            config_class (Type[ModuleConfiguration]): The configuration class for the module.
        """
        self._config_classes[module_name] = config_class

    def get_configuration_class(self, module_name: str) -> Optional[Type[ModuleConfiguration]]:
        """
        Get the configuration class for a module.

        Args:
            module_name (str): The name of the module.

        Returns:
            Optional[Type[ModuleConfiguration]]: The configuration class for the module,
                                               or None if no configuration is registered.
        """
        return self._config_classes.get(module_name)

    def create_default_configuration(self, module_name: str) -> Optional[ModuleConfiguration]:
        """
        Create a default configuration instance for a module.

        Args:
            module_name (str): The name of the module.

        Returns:
            Optional[ModuleConfiguration]: A new instance of the module's configuration with default values,
                                         or None if no configuration is registered.
        """
        config_class = self.get_configuration_class(module_name)
        if config_class:
            return config_class()
        return None

    def get_registered_modules(self) -> Dict[str, Type[ModuleConfiguration]]:
        """
        Get all registered module configurations.

        Returns:
            Dict[str, Type[ModuleConfiguration]]: A dictionary mapping module names to configuration classes.
        """
        return self._config_classes.copy()
