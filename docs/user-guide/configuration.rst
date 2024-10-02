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
