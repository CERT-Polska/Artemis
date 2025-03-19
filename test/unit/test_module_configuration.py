import unittest
from typing import Any, Dict

from artemis.modules.base.module_configuration import ModuleConfiguration


class TestModuleConfiguration(unittest.TestCase):
    def test_init_with_default_values(self) -> None:
        """Test initialization with default values."""
        config = ModuleConfiguration()
        self.assertTrue(config.enabled)

    def test_init_with_custom_values(self) -> None:
        """Test initialization with custom values."""
        config = ModuleConfiguration(enabled=False)
        self.assertFalse(config.enabled)

    def test_serialize(self) -> None:
        """Test serialization to dictionary."""
        config = ModuleConfiguration(enabled=False)
        serialized = config.serialize()
        self.assertIsInstance(serialized, dict)
        self.assertFalse(serialized["enabled"])

    def test_deserialize(self) -> None:
        """Test deserialization from dictionary."""
        config_dict: Dict[str, Any] = {"enabled": False}
        config = ModuleConfiguration.deserialize(config_dict)
        self.assertIsInstance(config, ModuleConfiguration)
        self.assertFalse(config.enabled)

    def test_deserialize_with_missing_values(self) -> None:
        """Test deserialization with missing values."""
        config_dict: Dict[str, Any] = {}
        config = ModuleConfiguration.deserialize(config_dict)
        self.assertTrue(config.enabled)

    def test_validate_valid_config(self) -> None:
        """Test validation with valid configuration."""
        config = ModuleConfiguration(enabled=True)
        self.assertTrue(config.validate())

    def test_validate_invalid_config(self) -> None:
        """Test validation with invalid configuration."""
        config = ModuleConfiguration()
        # Manually set an invalid value to test validation
        config.enabled = "not a boolean"  # type: ignore
        self.assertFalse(config.validate())

    def test_inheritance(self) -> None:
        """Test that the class can be inherited and extended."""

        class CustomModuleConfiguration(ModuleConfiguration):
            def __init__(self, enabled: bool = True, custom_option: str = "default") -> None:
                super().__init__(enabled=enabled)
                self.custom_option = custom_option

            def serialize(self) -> Dict[str, Any]:
                result = super().serialize()
                result["custom_option"] = self.custom_option
                return result

            @classmethod
            def deserialize(cls, config_dict: Dict[str, Any]) -> "CustomModuleConfiguration":
                return cls(
                    enabled=config_dict.get("enabled", True), custom_option=config_dict.get("custom_option", "default")
                )

            def validate(self) -> bool:
                return super().validate() and isinstance(self.custom_option, str)

        # Test initialization
        custom_config = CustomModuleConfiguration(enabled=False, custom_option="custom")
        self.assertFalse(custom_config.enabled)
        self.assertEqual(custom_config.custom_option, "custom")

        # Test serialization
        serialized = custom_config.serialize()
        self.assertFalse(serialized["enabled"])
        self.assertEqual(serialized["custom_option"], "custom")

        # Test deserialization
        deserialized = CustomModuleConfiguration.deserialize(serialized)
        self.assertFalse(deserialized.enabled)
        self.assertEqual(deserialized.custom_option, "custom")

        # Test validation
        self.assertTrue(deserialized.validate())
        deserialized.custom_option = 123  # type: ignore
        self.assertFalse(deserialized.validate())


if __name__ == "__main__":
    unittest.main()
