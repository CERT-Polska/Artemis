.. _generating-e-mails:

Generating e-mails to be sent
=============================
Artemis can generate e-mail reports containing a description of found vulnerabilities.

These reports won't contain everything found by Artemis - custom logic (residing in
``artemis/reporting/modules/``) will make an educated guess whether a vulnerability
is a true positive and interesting enough to be reported.

To generate these e-mails, use:

``./scripts/export_emails``

This script will produce **text messages ready to be sent** [1]_.

.. note ::
   Please keep in mind that the reporting script resolves domains and performs HTTP requests.

To view additional options, use ``./scripts/export_emails --help`` - for example, you will be able to change
language, filter reports by tag or skip sending messages that have already been sent.


Blocklist
^^^^^^^^^
You may exclude some domains from  being included in the messages (this doesn't influence the scanning). To
do that, use the ``--blocklist BLOCKLIST_FILE`` option. The blocklist file is a ``yaml`` file with the following syntax:

.. code-block:: yaml

    - domain: the domain to be filtered
      until: null or a date (YYYY-MM-DD) until which the filter will be active
      report_type: null (which will block all reports) or a string containing
         the type of reports that will be blocked (e.g. "misconfigured_email")

There may be multiple entries in a blocklist file, each with syntax described above.

.. [1] Besides the messages, the script will also produce a JSON file with vulnerability data, a jinja2 template and
    .po translation file - using these three files you can build the messages yourself.
