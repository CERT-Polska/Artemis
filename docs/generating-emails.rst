.. _generating-e-mails:

Generating e-mails to be sent
=============================
Artemis can generate e-mail reports containing a description of found vulnerabilities.

These reports won't contain everything found by Artemis - custom logic (residing in
``artemis/reporting/modules/``) will make an educated guess whether a vulnerability
is a true positive and interesting enough to be reported.

To generate these e-mails, use:

``./scripts/export_emails PREVIOUS_REPORTS_DIRECTORY``

``PREVIOUS_REPORTS_DIRECTORY`` is a directory where JSON files produced by previous script invocations
reside. This allows you to skip sending messages that have already been sent.

This script will produce **text messages ready to be sent** [1]_.

.. note ::
   Please keep in mind that the reporting script resolves domains and performs HTTP requests.

Additional export script options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Additionally, you may use the following optional parameters:

 - ``--tag TAG`` allows you to filter by the tag you provided when adding targets to be scanned. Only
   vulnerabilities from targets with this tag will be exported.
 - ``--language LANGUAGE`` would set the output report language (e.g. ``pl_PL`` or ``en_US``).
 - ``--verbose`` will print more information (e.g. whether some types of reports have not been observed for a long time),
 - ``--blocklist BLOCKLIST_FILE`` will filter vulnerabilities from being included in the messages (this doesn't influence the scanning). The
   blocklist file is a ``yaml`` file with the following syntax:

   .. code-block:: yaml

       - domain: the domain to be filtered
         until: null or a date (YYYY-MM-DD) until which the filter will be active
         report_type: null (which will block all reports) or a string containing
            the type of reports that will be blocked (e.g. "misconfigured_email")

.. [1] Besides the messages, the script will also produce a JSON file with vulnerability data, a jinja2 template and
    .po translation file - using these three files you can build the messages yourself.
