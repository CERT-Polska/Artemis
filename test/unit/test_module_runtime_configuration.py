import unittest
from typing import Any, Dict

from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration


class TestModuleRuntimeConfiguration(unittest.TestCase):
    def test_serialize(self) -> None:
        """Test serialization to dictionary."""
        config = ModuleRuntimeConfiguration()
        serialized = config.serialize()
        self.assertIsInstance(serialized, dict)
        self.assertEqual(serialized, {})

    def test_deserialize(self) -> None:
        """Test deserialization from dictionary."""
        config_dict: Dict[str, Any] = {}
        config = ModuleRuntimeConfiguration.deserialize(config_dict)
        self.assertIsInstance(config, ModuleRuntimeConfiguration)

    def test_validate(self) -> None:
        """Test validation."""
        config = ModuleRuntimeConfiguration()
        self.assertTrue(config.validate())  # Base validation should always return True

    def test_inheritance(self) -> None:
        """Test that the class can be inherited and extended."""

        class CustomModuleRuntimeConfiguration(ModuleRuntimeConfiguration):
            def __init__(self, custom_option: str = "default") -> None:
                super().__init__()
                self.custom_option = custom_option

            def serialize(self) -> Dict[str, Any]:
                result = super().serialize()
                result["custom_option"] = self.custom_option
                return result

            @classmethod
            def deserialize(cls, config_dict: Dict[str, Any]) -> "CustomModuleRuntimeConfiguration":
                return cls(custom_option=config_dict.get("custom_option", "default"))

            def validate(self) -> bool:
                return super().validate() and isinstance(self.custom_option, str)

        # Test initialization
        custom_config = CustomModuleRuntimeConfiguration(custom_option="custom")
        self.assertEqual(custom_config.custom_option, "custom")

        # Test serialization
        serialized = custom_config.serialize()
        self.assertEqual(serialized["custom_option"], "custom")

        # Test deserialization
        deserialized = CustomModuleRuntimeConfiguration.deserialize(serialized)
        self.assertEqual(deserialized.custom_option, "custom")

        # Test validation
        self.assertTrue(deserialized.validate())
        deserialized.custom_option = 123  # type: ignore
        self.assertFalse(deserialized.validate())


if __name__ == "__main__":
    unittest.main()
