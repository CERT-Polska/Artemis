import unittest
from typing import Any, Dict

from artemis.modules.base.module_configuration import ModuleConfiguration


class TestModuleConfiguration(unittest.TestCase):
    def test_serialize(self) -> None:
        """Test serialization to dictionary."""
        config = ModuleConfiguration()
        serialized = config.serialize()
        self.assertIsInstance(serialized, dict)
        self.assertEqual(serialized, {})

    def test_deserialize(self) -> None:
        """Test deserialization from dictionary."""
        config_dict: Dict[str, Any] = {}
        config = ModuleConfiguration.deserialize(config_dict)
        self.assertIsInstance(config, ModuleConfiguration)

    def test_validate(self) -> None:
        """Test validation."""
        config = ModuleConfiguration()
        self.assertTrue(config.validate())  # Base validation should always return True

    def test_inheritance(self) -> None:
        """Test that the class can be inherited and extended."""

        class CustomModuleConfiguration(ModuleConfiguration):
            def __init__(self, custom_option: str = "default") -> None:
                super().__init__()
                self.custom_option = custom_option

            def serialize(self) -> Dict[str, Any]:
                result = super().serialize()
                result["custom_option"] = self.custom_option
                return result

            @classmethod
            def deserialize(cls, config_dict: Dict[str, Any]) -> "CustomModuleConfiguration":
                return cls(custom_option=config_dict.get("custom_option", "default"))

            def validate(self) -> bool:
                return super().validate() and isinstance(self.custom_option, str)

        # Test initialization
        custom_config = CustomModuleConfiguration(custom_option="custom")
        self.assertEqual(custom_config.custom_option, "custom")

        # Test serialization
        serialized = custom_config.serialize()
        self.assertEqual(serialized["custom_option"], "custom")

        # Test deserialization
        deserialized = CustomModuleConfiguration.deserialize(serialized)
        self.assertEqual(deserialized.custom_option, "custom")

        # Test validation
        self.assertTrue(deserialized.validate())
        deserialized.custom_option = 123  # type: ignore
        self.assertFalse(deserialized.validate())


if __name__ == "__main__":
    unittest.main()
