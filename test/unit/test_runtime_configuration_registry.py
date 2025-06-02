import unittest
from typing import Any, Dict

from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration
from artemis.modules.base.runtime_configuration_registry import (
    RuntimeConfigurationRegistry,
)


class TestModuleConfig(ModuleRuntimeConfiguration):
    """Test configuration class for unit tests."""

    def __init__(self, test_option: str = "default") -> None:
        super().__init__()
        self.test_option = test_option

    def serialize(self) -> Dict[str, Any]:
        result = super().serialize()
        result["test_option"] = self.test_option
        return result

    @classmethod
    def deserialize(cls, config_dict: Dict[str, Any]) -> "TestModuleConfig":
        return cls(test_option=config_dict.get("test_option", "default"))

    def validate(self) -> bool:
        base_valid = super().validate()
        return base_valid and isinstance(self.test_option, str)


class AnotherTestConfig(ModuleRuntimeConfiguration):
    """Another test configuration class for unit tests."""

    pass


class TestRuntimeConfigurationRegistry(unittest.TestCase):
    def test_singleton_behavior(self) -> None:
        """Test that RuntimeConfigurationRegistry behaves as a singleton."""
        registry1 = RuntimeConfigurationRegistry()
        registry2 = RuntimeConfigurationRegistry()

        # The same instance should be returned
        self.assertIs(registry1, registry2)

        # Register a configuration in one instance
        registry1.register_configuration("test_module", TestModuleConfig)

        # It should be available in the other instance
        self.assertEqual(registry2.get_configuration_class("test_module"), TestModuleConfig)

    def test_register_configuration(self) -> None:
        """Test registering a configuration class."""
        registry = RuntimeConfigurationRegistry()

        # Clear any existing registrations from other tests
        registry._config_classes = {}

        registry.register_configuration("test_module", TestModuleConfig)

        # The configuration class should be registered
        self.assertIn("test_module", registry._config_classes)
        self.assertEqual(registry._config_classes["test_module"], TestModuleConfig)

    def test_get_configuration_class(self) -> None:
        """Test getting a configuration class."""
        registry = RuntimeConfigurationRegistry()

        # Clear any existing registrations from other tests
        registry._config_classes = {}

        # Register a configuration class
        registry.register_configuration("test_module", TestModuleConfig)

        # Get the configuration class
        config_class = registry.get_configuration_class("test_module")

        # Should return the correct class
        self.assertEqual(config_class, TestModuleConfig)

        # Should return None for non-existent module
        self.assertIsNone(registry.get_configuration_class("non_existent_module"))

    def test_create_default_configuration(self) -> None:
        """Test creating a default configuration."""
        registry = RuntimeConfigurationRegistry()

        # Clear any existing registrations from other tests
        registry._config_classes = {}

        # Register a configuration class
        registry.register_configuration("test_module", TestModuleConfig)

        # Create a default configuration
        config = registry.create_default_configuration("test_module")

        # Should return an instance of the correct class with default values
        self.assertIsInstance(config, TestModuleConfig)
        self.assertEqual(config.test_option, "default")  # type: ignore

        # Should return None for non-existent module
        self.assertIsNone(registry.create_default_configuration("non_existent_module"))

    def test_get_registered_modules(self) -> None:
        """Test getting all registered modules."""
        registry = RuntimeConfigurationRegistry()

        # Clear any existing registrations from other tests
        registry._config_classes = {}

        # Register multiple configuration classes
        registry.register_configuration("test_module1", TestModuleConfig)
        registry.register_configuration("test_module2", AnotherTestConfig)

        # Get all registered modules
        modules = registry.get_registered_modules()

        # Should return a copy of the dictionary
        self.assertIsNot(modules, registry._config_classes)

        # Should contain all registered modules
        self.assertEqual(len(modules), 2)
        self.assertEqual(modules["test_module1"], TestModuleConfig)
        self.assertEqual(modules["test_module2"], AnotherTestConfig)

        # Modifying the returned dictionary should not affect the registry
        modules["test_module3"] = TestModuleConfig
        self.assertNotIn("test_module3", registry._config_classes)


if __name__ == "__main__":
    unittest.main()
