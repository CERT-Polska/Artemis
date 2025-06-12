Configuration options
=====================

Artemis can be configured by setting the following variables in the ``.env`` file (in the form of ``VARIABLE_NAME=VARIABLE_VALUE``
directives, e.g. ``SCANNING_PACKETS_PER_SECOND=5``):

.. include:: config-docs.inc

Extra modules
-------------
Additionally, you can configure modules from the ``Artemis-modules-extra`` repository (https://github.com/CERT-Polska/Artemis-modules-extra) using
the configuration variables from https://github.com/CERT-Polska/Artemis-modules-extra/blob/main/extra_modules_config.py. The file to put them
in (``.env``) and the syntax (``VARIABLE_NAME=VARIABLE_VALUE``) is the same as for the core Artemis configuration.

Blocklist
---------
You may exclude some systems from being scanned or included in the reports. To do that, set the ``BLOCKLIST_FILE`` environment
variable to a path to a blocklist file (it needs to be placed in the ``./shared`` directory which is mounted to all scanning containers
as ``/shared``).

The blocklist file is a ``yaml`` file with the following syntax:

.. code-block:: yaml

    - mode: 'block_scanning_and_reporting' (to block both scanning and reporting) or
        'block_reporting_only' (if you want the scanning to be performed but want the
        issues to be skipped from automatic e-mail reports)
      domain_and_subdomains: null or the domain to be filtered (this will also filter its
         subdomains)
      subdomains: null or a domain - this setting will filter out only subdomains of this domain,
         but not the domain itself
      ip_range: null or the ip range to be filtered (to filter a single ip address,
        use the xxx.xxx.xxx.xxx/32 syntax)
      until: null or a date (YYYY-MM-DD) until which the filter will be active
      karton_name: null or the name of a scanning module

      report_target_should_contain: null or the string that must occur in the target for
        the report to be blocklisted - this parameter can be used only when 'mode' is set
        to 'block_reporting_only'.
      report_type: null (which will block all reports) or a string containing
         the type of reports that will be blocked (e.g. "misconfigured_email") - this
         parameter can be used only when 'mode' is 'block_reporting_only'.

There may be multiple entries in a blocklist file, each with syntax described above.

Advanced: Karton configuration
-------------------------------

Artemis is based on the Karton framework (https://github.com/CERT-Polska/karton). Please refer to the
`Karton documentation <https://karton-core.readthedocs.io/en/latest/getting_started.html#configuration>`_ for more information.

Module Runtime Configuration
----------------------------

The ``ModuleRuntimeConfiguration`` class serves as the base for all module-specific runtime configurations (that can be changed on a per-task basis)
in Artemis. It provides a standardized way to handle module configurations with serialization, deserialization, and validation capabilities.

Basic Usage
^^^^^^^^^^^

.. code-block:: python

    from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration

    # Create a configuration with default values
    config = ModuleRuntimeConfiguration()

    # Serialize to a dictionary
    config_dict = config.serialize()
    # Result: {}

    # Deserialize from a dictionary
    config = ModuleRuntimeConfiguration.deserialize({})

    # Validate configuration
    is_valid = config.validate()

Extending The Base Class
^^^^^^^^^^^^^^^^^^^^^^^^

To create a module-specific configuration, extend the ``ModuleRuntimeConfiguration`` class:

.. code-block:: python

    from typing import Dict, Any
    from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration

    class PortScannerConfiguration(ModuleRuntimeConfiguration):
        def __init__(
            self,
            timeout_ms: int = 5000,
            max_ports: int = 1000
        ) -> None:
            super().__init__()
            self.timeout_ms = timeout_ms
            self.max_ports = max_ports

        def serialize(self) -> Dict[str, Any]:
            result = super().serialize()
            result.update({
                "timeout_ms": self.timeout_ms,
                "max_ports": self.max_ports
            })
            return result

        @classmethod
        def deserialize(cls, config_dict: Dict[str, Any]) -> "PortScannerConfiguration":
            return cls(
                timeout_ms=config_dict.get("timeout_ms", 5000),
                max_ports=config_dict.get("max_ports", 1000)
            )

        def validate(self) -> bool:
            base_valid = super().validate()
            return (
                base_valid and
                isinstance(self.timeout_ms, int) and self.timeout_ms > 0 and
                isinstance(self.max_ports, int) and self.max_ports > 0
            )

API Reference
"""""""""""""

``serialize() -> Dict[str, Any]``
  Serializes the configuration to a dictionary format suitable for storage or transmission.

``deserialize(config_dict: Dict[str, Any]) -> ModuleConfiguration``
  Class method that creates a new configuration instance from a dictionary.

``validate() -> bool``
  Validates that the configuration is valid. Returns ``True`` if valid, ``False`` otherwise.

Integration with Module System
""""""""""""""""""""""""""""""

When developing a new module for Artemis, you should:

1. Create a custom configuration class extending ``ModuleRuntimeConfiguration``
2. Add module-specific configuration options
3. Override the ``serialize()``, ``deserialize()``, and ``validate()`` methods
4. Use the configuration in your module implementation

This approach ensures consistency in how module runtime configurations are handled throughout the system.

Runtime Configuration Registry
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``RuntimeConfigurationRegistry`` class provides a centralized registry for module runtime configurations. It is implemented as a singleton, ensuring that there's only one instance of the registry throughout the application.

Basic Usage
"""""""""""

.. code-block:: python

    from artemis.modules.base.runtime_configuration_registry import RuntimeConfigurationRegistry
    from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration

    # Define a custom configuration class
    class MyModuleConfiguration(ModuleRuntimeConfiguration):
        # Custom configuration implementation
        pass

    # Get the singleton registry instance
    registry = RuntimeConfigurationRegistry()

    # Register a configuration class for a module
    registry.register_configuration("my_module", MyModuleConfiguration)

    # Get the configuration class for a module
    config_class = registry.get_configuration_class("my_module")

    # Create a default configuration instance
    default_config = registry.create_default_configuration("my_module")

    # Get all registered modules
    modules = registry.get_registered_modules()

API Reference
"""""""""""""

.. code-block:: python

    RuntimeConfigurationRegistry()

Always returns the same singleton instance.

``register_configuration(module_name: str, config_class: Type[ModuleConfiguration]) -> None``
  Registers a configuration class for a module.

``get_configuration_class(module_name: str) -> Optional[Type[ModuleConfiguration]]``
  Gets the configuration class for a module. Returns ``None`` if no configuration is registered.

``create_default_configuration(module_name: str) -> Optional[ModuleConfiguration]``
  Creates a default configuration instance for a module. Returns ``None`` if no configuration is registered.

``get_registered_modules() -> Dict[str, Type[ModuleConfiguration]]``
  Gets all registered module configurations as a dictionary mapping module names to configuration classes.

Integration with Module System
""""""""""""""""""""""""""""""

When integrating with the Artemis module system:

1. Register module-specific configuration classes with the registry
2. Use the registry to create default configurations for modules
3. Access module configurations through the registry

The registry provides a centralized way to manage module configurations, making it easier to create, retrieve, and manage configurations for different modules in the system.
