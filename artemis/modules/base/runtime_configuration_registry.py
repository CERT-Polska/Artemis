from typing import Dict, Optional, Type

from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration


class RuntimeConfigurationRegistry:
    """
    Singleton registry for managing module runtime configurations in Artemis.

    This class maintains a mapping between module names and their
    configuration classes, allowing for centralized configuration management.
    """

    # Singleton instance
    _instance = None

    _config_classes: Dict[str, Type[ModuleRuntimeConfiguration]] = {}

    # Private constructor
    def __new__(cls) -> "RuntimeConfigurationRegistry":
        """Create a singleton instance if one doesn't exist."""
        if cls._instance is None:
            cls._instance = super(RuntimeConfigurationRegistry, cls).__new__(cls)
            cls._instance._config_classes = {}
        return cls._instance

    def register_configuration(self, module_name: str, config_class: Type[ModuleRuntimeConfiguration]) -> None:
        """
        Register a configuration class for a module.

        Args:
            module_name (str): The name of the module.
            config_class (Type[ModuleRuntimeConfiguration]): The configuration class for the module.
        """
        self._config_classes[module_name] = config_class

    def get_configuration_class(self, module_name: str) -> Optional[Type[ModuleRuntimeConfiguration]]:
        """
        Get the configuration class for a module.

        Args:
            module_name (str): The name of the module.

        Returns:
            Optional[Type[ModuleRuntimeConfiguration]]: The configuration class for the module,
                                               or None if no configuration is registered.
        """
        return self._config_classes.get(module_name)

    def create_default_configuration(self, module_name: str) -> Optional[ModuleRuntimeConfiguration]:
        """
        Create a default configuration instance for a module.

        Args:
            module_name (str): The name of the module.

        Returns:
            Optional[ModuleRuntimeConfiguration]: A new instance of the module's configuration with default values,
                                         or None if no configuration is registered.
        """
        config_class = self.get_configuration_class(module_name)
        if config_class:
            return config_class()
        return None

    def get_registered_modules(self) -> Dict[str, Type[ModuleRuntimeConfiguration]]:
        """
        Get all registered module configurations.

        Returns:
            Dict[str, Type[ModuleRuntimeConfiguration]]: A dictionary mapping module names to configuration classes.
        """
        return self._config_classes.copy()
