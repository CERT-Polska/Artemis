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

Module Configuration
-------------------

The ``ModuleConfiguration`` class serves as the base for all module-specific configurations in Artemis. It provides a standardized way to handle module configurations with serialization, deserialization, and validation capabilities.

Basic Usage
~~~~~~~~~~

.. code-block:: python

    from artemis.modules.base.module_configuration import ModuleConfiguration

    # Create a configuration with default values
    config = ModuleConfiguration()  # enabled=True by default

    # Create a configuration with custom values
    config = ModuleConfiguration(enabled=False)

    # Serialize to a dictionary
    config_dict = config.serialize()
    # Result: {"enabled": false}

    # Deserialize from a dictionary
    config = ModuleConfiguration.deserialize({"enabled": False})

    # Validate configuration
    is_valid = config.validate()

Extending The Base Class
~~~~~~~~~~~~~~~~~~~~~~~

To create a module-specific configuration, extend the ``ModuleConfiguration`` class:

.. code-block:: python

    from typing import Dict, Any
    from artemis.modules.base.module_configuration import ModuleConfiguration

    class PortScannerConfiguration(ModuleConfiguration):
        def __init__(
            self, 
            enabled: bool = True,
            timeout_ms: int = 5000,
            max_ports: int = 1000
        ) -> None:
            super().__init__(enabled=enabled)
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
                enabled=config_dict.get("enabled", True),
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
~~~~~~~~~~~~

Constructor
^^^^^^^^^^

.. code-block:: python

    ModuleConfiguration(enabled: bool = True)

- ``enabled``: Controls whether the module is enabled. Defaults to ``True``.

Methods
^^^^^^^

``serialize() -> Dict[str, Any]``
  Serializes the configuration to a dictionary format suitable for storage or transmission.

``deserialize(config_dict: Dict[str, Any]) -> ModuleConfiguration``
  Class method that creates a new configuration instance from a dictionary.

``validate() -> bool``
  Validates that the configuration is valid. Returns ``True`` if valid, ``False`` otherwise.

Integration with Module System
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When developing a new module for Artemis, you should:

1. Create a custom configuration class extending ``ModuleConfiguration``
2. Add module-specific configuration options
3. Override the ``serialize()``, ``deserialize()``, and ``validate()`` methods
4. Use the configuration in your module implementation

This approach ensures consistency in how module configurations are handled throughout the system.

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
