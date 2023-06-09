Quick Start
===========

Currently, only Docker Compose based deployment is supported.

More production-ready way to deploy Artemis will be to use Kubernetes - you may follow
the progress or help with that task on: https://github.com/CERT-Polska/Artemis/issues/204.

Using Docker Compose
--------------------

To start Artemis simply execute following 2 commands in your terminal:

.. code-block:: console

   cp env.example .env  # you may also configure the settings (e.g. by providing a User-Agent to override the default one)
   docker compose up --build

After that you should be able to access the Artemis dashboard at ``localhost:5000``.

**If you want to start multiple instances of a module to speed up scanning, use a command such as:**

.. code-block:: console

   docker compose up --build \
       --scale=karton-nuclei=10 \
       --scale=karton-bruter=10 \
       --scale=karton-port_scanner=10

.. note ::
   If you get an error that ``docker compose`` is not a valid command, try ``docker-compose``.

Adding targets to scan
----------------------

Select ``Add targets`` from the top navigation bar. Artemis takes input in the form
of entries separated with newlines. Artemis works with both IPs and domains. If
a URL is provided, the domain from this URL will be scanned.

To be later able to filter various types of targets, provide a tag in the `Tag` field.

Viewing results
---------------

To view results, click the ``View results`` link in the top navigation bar.

.. _generating-e-mails:

Generating e-mails to be sent
-----------------------------
Artemis has a feature to generate e-mail reports containing a description of found vulnerabilities.

These reports won't contain everything found by Artemis - custom logic (residing in
``artemis/reporting/modules/``) will make an educated guess whether a vulnerability
is a true positive and interesting enough to be reported.

To generate these e-mails, use:

``./scripts/export_emails ALREADY_EXISTING_REPORT_DIRECTORY TAG``

 - ``ALREADY_EXISTING_REPORT_DIRECTORY`` is a directory where JSON files produced by previous script invocations
   reside. This allows you to skip sending messages that have already been sent.
 - ``TAG`` is the tag you provided when adding targets to be scanned. Only vulnerabilities from targets with this tag will be exported.

This script will produce **text messages ready to be sent** [1]_.

.. note ::
   Please keep in mind that the reporting script resolves domains and performs HTTP requests.

Additional export script options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Additionally, you may use the following optional parameters:

 - ``--language LANGUAGE`` would set the output report language (e.g. ``pl_PL`` or ``en_US``).
 - ``--blocklist BLOCKLIST_FILE`` will filter vulnerabilities from being included in the messages (this doesn't influence the scanning). The
   blocklist file is a ``yaml`` file with the following syntax:

   .. code-block:: yaml

       - domain: the domain to be filtered
         until: null or a date (YYYY-MM-DD) until which the filter will be active
         report_type: null (which will block all reports) or a string containing
            the type of reports that will be blocked (e.g. "misconfigured_email")

.. [1] Besides the messages, the script will also produce a JSON file with vulnerability data, a jinja2 template and
    .po translation file - using these three files you can build the messages yourself.
